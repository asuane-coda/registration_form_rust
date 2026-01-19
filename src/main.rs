use actix_files as fs;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, Result};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use actix_web::error::ErrorInternalServerError;
use tera::{Tera, Context};
use actix_session::Session;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;
use bcrypt::{hash, DEFAULT_COST};
use bcrypt::verify;
use actix_web::get;
use actix_multipart::Multipart;
use futures_util::stream::StreamExt;
use std::io::Cursor;
use base64::engine::general_purpose;
use base64::Engine;
use image::{ImageFormat, imageops::FilterType};


#[derive(Deserialize)]
struct FormData {
    name: String,
    email: String,
}

#[derive(sqlx::FromRow, serde::Serialize)]
struct User {
    id: i32,
    name: String,
    email: String,
    created_at: chrono::NaiveDate,
    profile_picture: Option<String>,
    phone_number: Option<String>,
    address: Option<String>,
    emergency_contact: Option<String>,
}

#[derive(sqlx::FromRow, serde::Serialize)]
struct Payment {
    id: i32,
    user_id: i32,
    amount: f64,
    status: String,
    reference: Option<String>,
    created_at: chrono::NaiveDateTime,
}

#[derive(sqlx::FromRow, serde::Serialize)]
struct PaymentWithUser {
    payment_id: i32,
    amount: f64,
    status: String,
    reference: Option<String>,
    created_at: chrono::NaiveDateTime,
    user_name: String,
    user_email: String,
}

#[derive(serde::Serialize)]
struct PaystackInitializeRequest {
    email: String,
    amount: String, // Amount in kobo (as string or int, but Paystack accepts string)
    callback_url: String,
    reference: String,
}

#[derive(serde::Deserialize)]
struct PaystackInitializeResponseData {
    authorization_url: String,
    access_code: String,
    reference: String,
}

#[derive(serde::Deserialize)]
struct PaystackInitializeResponse {
    status: bool,
    message: String,
    data: Option<PaystackInitializeResponseData>,
}

#[derive(serde::Deserialize)]
struct PaystackVerifyResponseData {
    status: String,
    reference: String,
    amount: i64, // In kobo
}

#[derive(serde::Deserialize)]
struct PaystackVerifyResponse {
    status: bool,
    message: String,
    data: Option<PaystackVerifyResponseData>,
}

const PAYSTACK_SECRET_KEY: &str = "sk_test_1234567890abcdef1234567890abcdef12345678"; // PLACEHOLDER!

#[derive(Deserialize)]
struct PaymentForm {
    // amount is now fixed, but we might keep this if we want flexible options later, 
    // but for this task we ignore it or make it optional.
    #[serde(default)]
    _amount: Option<f64>, 
}

// HANDLE FORM SUBMISSION
async fn submit_form(
    mut payload: Multipart,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let mut name = "".to_string();
    let mut email = "".to_string();
    let mut password = "".to_string();
    let mut profile_picture: Option<String> = None;
    let mut phone_number: Option<String> = None;
    let mut address: Option<String> = None;
    let mut emergency_contact: Option<String> = None;

    while let Some(item) = payload.next().await {
        let mut field = item.unwrap();
        let content_disposition = field.content_disposition();
        let field_name = content_disposition.get_name().unwrap();

        match field_name {
            "name" => {
                let mut bytes = Vec::new();
                while let Some(chunk) = field.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                name = String::from_utf8(bytes).unwrap();
            }
            "email" => {
                let mut bytes = Vec::new();
                while let Some(chunk) = field.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                email = String::from_utf8(bytes).unwrap();
            }
            "password" => {
                let mut bytes = Vec::new();
                while let Some(chunk) = field.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                password = String::from_utf8(bytes).unwrap();
            }
            "phone_number" => {
                let mut bytes = Vec::new();
                while let Some(chunk) = field.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                let s = String::from_utf8(bytes).unwrap();
                let s = s.trim();
                if !s.is_empty() {
                    phone_number = Some(s.to_string());
                }
            }
            "address" => {
                let mut bytes = Vec::new();
                while let Some(chunk) = field.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                let s = String::from_utf8(bytes).unwrap();
                let s = s.trim();
                if !s.is_empty() {
                    address = Some(s.to_string());
                }
            }
            "emergency_contact" => {
                let mut bytes = Vec::new();
                while let Some(chunk) = field.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                let s = String::from_utf8(bytes).unwrap();
                let s = s.trim();
                if !s.is_empty() {
                    emergency_contact = Some(s.to_string());
                }
            }
            "profile_picture" => {
                let mut bytes = Vec::new();
                while let Some(chunk) = field.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                
                if !bytes.is_empty() {
                    let img = image::load_from_memory(&bytes).unwrap();
                    let resized_img = img.resize_to_fill(100, 100, FilterType::Lanczos3);
                    let mut buf = Cursor::new(Vec::new());
                    resized_img.write_to(&mut buf, ImageFormat::Png).unwrap();
                    profile_picture = Some(general_purpose::STANDARD.encode(buf.into_inner()));
                }
            }
            _ => (),
        }
    }

    let email_message = Message::builder()
        .from("The Rust Team <ekoiasuanetop@gmail.com>".parse().unwrap())
        .to(format!("{} <{}>", name, email).parse().unwrap())
        .subject("Welcome!")
        .body(format!("Dear {}. Thank you for registering!\nFrom the Rust team", name))
        .unwrap();

    let existing_user = sqlx::query_scalar::<_, i32>(
    "SELECT id FROM users WHERE email = $1"
)
    .bind(&email)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(ErrorInternalServerError)?;

    if existing_user.is_some() {
        return Ok(HttpResponse::Conflict().body("Email already registered"));
    }

    if password.is_empty() {
        return Ok(HttpResponse::BadRequest().body("Password is required"));
    }

      // Hash password
    let password_hash = hash(&password, DEFAULT_COST)
        .map_err(|_| ErrorInternalServerError("Password hashing failed"))?;

     // Insert new user

   let new_user: (i32,) = sqlx::query_as(
    "INSERT INTO users (name, email, password_hash, profile_picture, phone_number, address, emergency_contact) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
)
    .bind(&name)
    .bind(&email)
    .bind(&password_hash)
    .bind(&profile_picture)
    .bind(&phone_number)
    .bind(&address)
    .bind(&emergency_contact)
    .fetch_one(pool.get_ref())
    .await
    .map_err(ErrorInternalServerError)?;

    let new_user_id = new_user.0;

    let creds = Credentials::new(
        "ekoiasuanetop@gmail.com".to_string(),
        "skabqfjdtoaqaopi".to_string(),
    );

    let tls_parameters = TlsParameters::new("smtp.gmail.com".to_string()).unwrap();
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .port(587)
        .tls(Tls::Required(tls_parameters))
        .credentials(creds)
        .build();

    let response_body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Success</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body style="font-family: 'Inter', Arial, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 40px 20px; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);">
    <div class="container message-container" style="background-color: #ffffff; padding: 3.5rem; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.08); text-align: center; max-width: 520px; width: 100%; border: 1px solid rgba(0, 0, 0, 0.05);">
        <h1 style="margin-bottom: 2rem; font-size: 2.2rem; font-weight: 800; letter-spacing: -1px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">Registration Successful!</h1>
        <p style="color: #495057; margin-bottom: 2.5rem; font-size: 1.1rem; font-weight: 500;">Registration saved and email sent!</p>
        
        <a href="/login" class="button" style="
            display: inline-block; 
            padding: 1.2rem 2rem; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            text-decoration: none; 
            border: none; 
            border-radius: 12px; 
            cursor: pointer; 
            font-size: 1rem; 
            font-weight: 800; 
            width: auto;
            max-width: 250px;
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.3); 
            text-transform: uppercase; 
            letter-spacing: 1.2px; 
            transition: all 0.3s ease;
        ">Login</a>
    </div>
</body>
</html>"#
    );

    match mailer.send(&email_message) {
        Ok(_) => Ok(HttpResponse::Ok().content_type("text/html").body(response_body)),
        Err(e) => {
            println!("Email send error: {:?}", e);
            Ok(HttpResponse::InternalServerError().body(format!("Failed to send email: {}", e)))
        }
    }
}


// MAKE PAYMENT (Initialize Paystack)
async fn make_payment(
    session: Session,
    pool: web::Data<PgPool>,
) -> impl Responder {
    let user_id: i32 = match session.get("user_id").unwrap_or(None) {
        Some(id) => id,
        None => return HttpResponse::Found().append_header(("Location", "/login")).finish(),
    };

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await;

    let user = match user {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().body("User not found"),
    };

    // Fixed amount: 5000 NGN = 500000 kobo
    let amount_ngn = 5000.0;
    let amount_kobo = "500000"; 
    let reference = uuid::Uuid::new_v4().to_string();
    
    // In a real app, use an environment variable for the host
    let callback_url = format!("http://127.0.0.1:8080/payment/callback"); 

    let client = reqwest::Client::new();
    let params = PaystackInitializeRequest {
        email: user.email.clone(),
        amount: amount_kobo.to_string(),
        callback_url,
        reference: reference.clone(),
    };

    // Use env var or fallback for demo
    let secret_key = std::env::var("PAYSTACK_SECRET_KEY").unwrap_or_else(|_| PAYSTACK_SECRET_KEY.to_string());

    let res = client.post("https://api.paystack.co/transaction/initialize")
        .header("Authorization", format!("Bearer {}", secret_key))
        .header("Content-Type", "application/json")
        .json(&params)
        .send()
        .await;

    match res {
        Ok(response) => {
            if response.status().is_success() {
                let paystack_res: PaystackInitializeResponse = response.json().await.unwrap();
                if let Some(data) = paystack_res.data {
                    // Save pending payment
                    let _ = sqlx::query(
                        "INSERT INTO payments (user_id, amount, status, reference) VALUES ($1, $2, $3, $4)"
                    )
                    .bind(user_id)
                    .bind(amount_ngn)
                    .bind("Pending")
                    .bind(&reference)
                    .execute(pool.get_ref())
                    .await;

                    // Redirect to Paystack
                    return HttpResponse::Found().append_header(("Location", data.authorization_url)).finish();
                }
            }
            HttpResponse::InternalServerError().body("Failed to initialize payment with Paystack")
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Request failed: {}", e)),
    }
}

#[derive(Deserialize)]
struct PaymentCallback {
    reference: String,
}

// VERIFY PAYMENT (Callback)
async fn verify_payment(
    pool: web::Data<PgPool>,
    query: web::Query<PaymentCallback>,
) -> impl Responder {
    let reference = &query.reference;

    let secret_key = std::env::var("PAYSTACK_SECRET_KEY").unwrap_or_else(|_| PAYSTACK_SECRET_KEY.to_string());
    let client = reqwest::Client::new();
    
    let res = client.get(format!("https://api.paystack.co/transaction/verify/{}", reference))
        .header("Authorization", format!("Bearer {}", secret_key))
        .send()
        .await;

    match res {
        Ok(response) => {
            if response.status().is_success() {
                let paystack_res: PaystackVerifyResponse = response.json().await.unwrap();
                if let Some(data) = paystack_res.data {
                    if data.status == "success" {
                        // Update payment status
                        let _ = sqlx::query(
                            "UPDATE payments SET status = 'Completed' WHERE reference = $1"
                        )
                        .bind(reference)
                        .execute(pool.get_ref())
                        .await;

                        return HttpResponse::Found().append_header(("Location", "/profile")).finish();
                    }
                }
            }
            HttpResponse::BadRequest().body("Payment verification failed")
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Verification request failed: {}", e)),
    }
}

// LIST USERS
async fn list_users(
    session: Session,
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>,
) -> impl Responder {
    // 1. Check if user is the admin
    let email: Option<String> = session.get("email").unwrap_or(None);
    if email.as_deref() != Some("admin@gmail.com") {
        // If not admin, redirect to login page
        return HttpResponse::Found().append_header(("Location", "/login")).finish();
    }

    // 2. Fetch and display users for the admin
    let users = sqlx::query_as::<_, User>("SELECT id, name, email, created_at, profile_picture, phone_number, address, emergency_contact FROM users")
        .fetch_all(pool.get_ref())
        .await
        .unwrap();

    let mut ctx = tera::Context::new();
    ctx.insert("users", &users);

    let rendered = tmpl.render("users.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}


// LIST PAYMENTS (ADMIN)
async fn list_payments(
    session: Session,
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>,
) -> impl Responder {
    // 1. Check if user is the admin
    let email: Option<String> = session.get("email").unwrap_or(None);
    if email.as_deref() != Some("admin@gmail.com") {
        return HttpResponse::Found().append_header(("Location", "/login")).finish();
    }

    // 2. Fetch all payments with user details
    let payments = sqlx::query_as::<_, PaymentWithUser>(
        r#"
        SELECT p.id as payment_id, p.amount, p.status, p.reference, p.created_at, u.name as user_name, u.email as user_email
        FROM payments p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap();

    let mut ctx = Context::new();
    ctx.insert("payments", &payments);

    let rendered = tmpl.render("admin_payments.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}


// VIEW USER PROFILE
async fn view_user(
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>,
    path: web::Path<i32>,
) -> impl Responder {
    let requested_id = path.into_inner();

    // Fetch the user
    let user = sqlx::query_as::<_, User>("SELECT id, name, email, created_at, profile_picture, phone_number, address, emergency_contact FROM users WHERE id = $1")
        .bind(requested_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap();

    let mut ctx = Context::new();
    ctx.insert("user", &user);

    let rendered = tmpl.render("profile.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}


// EDIT USER FORM
pub async fn edit_user_form(
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>,
    path: web::Path<i32>,
) -> impl Responder {
    let user_id = path.into_inner();

    let user = sqlx::query_as::<_, User>("SELECT id, name, email, created_at, profile_picture, phone_number, address, emergency_contact FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await;

    match user {
        Ok(user) => {
            let mut ctx = Context::new();
            ctx.insert("user", &user);

            let rendered = tmpl.render("edit_user.html", &ctx).unwrap();
            HttpResponse::Ok().content_type("text/html").body(rendered)
        }
        Err(_) => HttpResponse::NotFound().body("User not found"),
    }
}


#[derive(Deserialize)]
struct EditForm {
    name: String,
    phone_number: Option<String>,
    address: Option<String>,
    emergency_contact: Option<String>,
}

// HANDLE EDIT FORM SUBMISSION
async fn update_user_profile(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    form: web::Form<EditForm>,
) -> impl Responder {
    let user_id = path.into_inner();

    let phone_number = form.phone_number.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string());
    let address = form.address.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string());
    let emergency_contact = form.emergency_contact.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string());

    let result = sqlx::query(
        "UPDATE users SET name = $1, phone_number = $2, address = $3, emergency_contact = $4 WHERE id = $5"
    )
    .bind(&form.name)
    .bind(phone_number)
    .bind(address)
    .bind(emergency_contact)
    .bind(user_id)
    .execute(pool.get_ref())
    .await;
    
    match result {
        Ok(_) => HttpResponse::Found().append_header(("Location", format!("/users/{}/edit", user_id))).finish(),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed: {}", e)),
    }
}

// DOWNLOAD PAYMENT RECEIPT
async fn download_receipt(
    session: Session,
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
) -> impl Responder {
    let payment_id = path.into_inner();

    // 1. Check if user is logged in
    let user_id: i32 = match session.get("user_id").unwrap_or(None) {
        Some(id) => id,
        None => return HttpResponse::Found().append_header(("Location", "/login")).finish(),
    };

    // 2. Fetch payment and verify ownership
    let payment = sqlx::query_as::<_, Payment>(
        "SELECT id, user_id, amount, status, reference, created_at FROM payments WHERE id = $1"
    )
    .bind(payment_id)
    .fetch_optional(pool.get_ref())
    .await;

    match payment {
        Ok(Some(p)) => {
            // Check if user owns the payment or is admin
            let email: Option<String> = session.get("email").unwrap_or(None);
            let is_admin = email.as_deref() == Some("admin@gmail.com");

            if p.user_id != user_id && !is_admin {
                 return HttpResponse::Forbidden().body("You do not have permission to view this receipt.");
            }

            // Generate Receipt Content
            let receipt_content = format!(
                "PAYMENT RECEIPT\n\
                --------------------------------\n\
                Payment ID: {}\n\
                Date: {}\n\
                Reference: {}\n\
                Amount: ₦{:.2}\n\
                Status: {}\n\
                --------------------------------\n\
                Thank you for your payment!",
                p.id, p.created_at, p.reference.unwrap_or_default(), p.amount, p.status
            );

            HttpResponse::Ok()
                .insert_header(("Content-Type", "text/plain"))
                .insert_header(("Content-Disposition", format!("attachment; filename=\"receipt_{}.txt\"", p.id)))
                .body(receipt_content)
        },
        Ok(None) => HttpResponse::NotFound().body("Payment not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}


// DOWNLOAD USERS CSV
pub async fn download_users_csv(
    session: Session,
    pool: web::Data<PgPool>
) -> impl Responder {
    // 1. Check if user is the admin
    let email: Option<String> = session.get("email").unwrap_or(None);
    if email.as_deref() != Some("admin@gmail.com") {
        // If not admin, redirect to login page
        return HttpResponse::Found().append_header(("Location", "/login")).finish();
    }

    // 2. Fetch all users
   let users = sqlx::query_as::<_, User>("SELECT id, name, email, created_at FROM users")
    .fetch_all(pool.get_ref())
    .await;

    if let Err(e) = users {
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    let users = users.unwrap();

    // Build CSV string
    let mut csv_data = String::from("id,name,email,created_at\n");

    for user in users {
        csv_data.push_str(&format!(
            "{},{},{},{}\n",
            user.id,
            user.name,
            user.email,
            user.created_at
        ));
    }

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/csv"))
        .insert_header(("Content-Disposition", "attachment; filename=\"users.csv\""))
        .body(csv_data)
}


// LOGIN REQUEST 

#[derive(Deserialize)]
    pub struct LoginRequest {
    pub email: String,
    #[serde(default)]
    pub password: String,
}

pub async fn login(
    form: web::Form<LoginRequest>,
    session: Session,
    pool: web::Data<sqlx::PgPool>,
) -> actix_web::Result<HttpResponse> {
    if form.password.is_empty() {
        return Ok(HttpResponse::BadRequest().body("Password is required"));
    }
    // Fetch user by email
    let user = sqlx::query_as::<_, (i32, String)>(
        "SELECT id, password_hash FROM users WHERE email = $1"
    )
    .bind(&form.email)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|_| ErrorInternalServerError("Login failed"))?;

    let (id, password_hash) = match user {
        Some(u) => u,
        None => return Ok(HttpResponse::Unauthorized().body("Invalid email or password")),
    };

    // Verify password
    let is_valid = verify(&form.password, &password_hash)
          .map_err(|_| ErrorInternalServerError("Password verification failed"))?;

    if !is_valid {
        return Ok(HttpResponse::Unauthorized().body("Invalid email or password"));
    }

    // Store user ID and role in session
    session.insert("user_id", id)?;
    session.insert("email", form.email.clone())?;


    // Redirect to profile
    Ok(HttpResponse::Found()
        .append_header(("Location", "/dashboard"))
        .finish())

}

//LOGIN FORM

async fn login_page(tmpl: web::Data<Tera>) -> impl Responder {
    let ctx = Context::new();
    let rendered = tmpl.render("login_form.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

#[get("/profile")]
async fn profile(
    session: Session,
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>
) -> actix_web::Result<HttpResponse> { // Use explicit actix_web::Result to fix compiler error
    
    // 1. Check if user is logged in
    let user_id: i32 = match session.get("user_id").unwrap_or(None) {
        Some(id) => id,
        None => {
            // If not logged in, redirect to login page
            return Ok(HttpResponse::Found().append_header(("Location", "/login")).finish());
        }
    };

    // 2. Fetch user details from DB
    let user = sqlx::query_as::<_, User>("SELECT id, name, email, created_at, profile_picture, phone_number, address, emergency_contact FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(ErrorInternalServerError)?;

    // 3. Render the profile.html template
    match user {
        Some(u) => {
            let mut ctx = Context::new();
            ctx.insert("user", &u);
            
            // Check if the user is the admin
            let is_admin = u.email == "admin@gmail.com";
            ctx.insert("is_admin", &is_admin);

            // Render template (allows {{ user.name }} and {{ is_admin }} to work)
            let rendered = tmpl.render("profile.html", &ctx)
                .map_err(ErrorInternalServerError)?;
                
            Ok(HttpResponse::Ok().body(rendered))
        }
        None => {
            // Session exists but user not in DB? Force logout/login
            Ok(HttpResponse::Found().append_header(("Location", "/login")).finish())
        }
    }
}

#[get("/dashboard")]
async fn dashboard(
    session: Session,
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>
) -> actix_web::Result<HttpResponse> {
    
    // 1. Check if user is logged in
    let user_id: i32 = match session.get("user_id").unwrap_or(None) {
        Some(id) => id,
        None => {
            return Ok(HttpResponse::Found().append_header(("Location", "/login")).finish());
        }
    };

    // 2. Fetch user details from DB
    let user = sqlx::query_as::<_, User>("SELECT id, name, email, created_at, profile_picture, phone_number, address, emergency_contact FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(ErrorInternalServerError)?;

    match user {
        Some(u) => {
            let mut ctx = Context::new();
            ctx.insert("user", &u);
            
            let is_admin = u.email == "admin@gmail.com";
            ctx.insert("is_admin", &is_admin);

            let rendered = tmpl.render("dashboard.html", &ctx)
                .map_err(ErrorInternalServerError)?;
                
            Ok(HttpResponse::Ok().body(rendered))
        }
        None => {
            Ok(HttpResponse::Found().append_header(("Location", "/login")).finish())
        }
    }
}

#[get("/payments")]
async fn user_payments(
    session: Session,
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>
) -> actix_web::Result<HttpResponse> {
    
    // 1. Check if user is logged in
    let user_id: i32 = match session.get("user_id").unwrap_or(None) {
        Some(id) => id,
        None => {
            return Ok(HttpResponse::Found().append_header(("Location", "/login")).finish());
        }
    };

    // 2. Fetch user's payments
    let payments = sqlx::query_as::<_, Payment>(
        "SELECT id, user_id, amount, status, reference, created_at FROM payments WHERE user_id = $1 ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(ErrorInternalServerError)?;

    let mut ctx = Context::new();
    ctx.insert("payments", &payments);

    let rendered = tmpl.render("payments.html", &ctx)
        .map_err(ErrorInternalServerError)?;
        
    Ok(HttpResponse::Ok().body(rendered))
}





#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Could not connect to database");

    // Create payments table if it doesn't exist
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS payments (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            amount DOUBLE PRECISION NOT NULL,
            status VARCHAR(50) NOT NULL,
            reference VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        "#
    )
    .execute(&pool)
    .await
    .expect("Failed to create payments table");

    // Ensure reference column exists (migration for existing tables)
    let _ = sqlx::query("ALTER TABLE payments ADD COLUMN IF NOT EXISTS reference VARCHAR(100)")
        .execute(&pool)
        .await;

    // Add new columns to users table
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(50)")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS emergency_contact VARCHAR(100)")
        .execute(&pool)
        .await;

    let tera = Tera::new("static/**/*html")
        .expect("Failed to initialize Tera templates");

    // Create Redis store BEFORE HttpServer::new
    // let redis_store = RedisSessionStore::new("redis://127.0.0.1:6379")
    //     .await
    //     .expect("Failed to connect to Redis");
    
    let key = Key::from(
        std::env::var("SESSION_SECRET")
            .expect("SESSION_SECRET must be set")
            .as_bytes()
    );

    HttpServer::new(move || {
        App::new()
           .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(tera.clone()))
            
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    key.clone(),
                )
                .cookie_secure(false)
                .build()
            )

            // Form submission
            .route("/submit", web::post().to(submit_form))

            // List users
            .route("/users", web::get().to(list_users))

            //Download users list
            .route("/users/download", web::get().to(download_users_csv))

            // View user profile
            .route("/users/{id}", web::get().to(view_user))

            // Edit user (GET + POST)
            .route("/users/{id}/edit", web::get().to(edit_user_form))
            .route("/users/{id}/edit", web::post().to(update_user_profile))

            // Login
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login))

            // Payments
            .route("/payment/submit", web::post().to(make_payment))
            .route("/payment/callback", web::get().to(verify_payment)) // New callback route
            .route("/admin/payments", web::get().to(list_payments))
            .route("/payment/{id}/receipt", web::get().to(download_receipt))

            


            // Static files
            .service(profile)
            .service(dashboard)
            .service(user_payments)
            .service(fs::Files::new("/", "./static").index_file("index.html"))
            

    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}