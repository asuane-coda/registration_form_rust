use actix_files as fs;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, Result};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use actix_web::error::ErrorInternalServerError;
use tera::{Tera, Context};
use actix_session::Session;
use actix_session::{SessionMiddleware, storage::RedisSessionStore};
use actix_web::cookie::Key;
use bcrypt::{hash, DEFAULT_COST};
use bcrypt::verify;
use actix_web::get;


#[derive(Deserialize)]
struct FormData {
    name: String,
    email: String,
    #[serde(default)]
    password: String,
}

#[derive(sqlx::FromRow, serde::Serialize)]
struct User {
    id: i32,
    name: String,
    email: String,
    created_at: chrono::NaiveDate,
   
}

// HANDLE FORM SUBMISSION
async fn submit_form(
    form: web::Form<FormData>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let email = Message::builder()
        .from("The Rust Team <your.email@gmail.com>".parse().unwrap())
        .to(format!("{} <{}>", form.name, form.email).parse().unwrap())
        .subject("Welcome!")
        .body(format!("Dear {}. Thank you for registering!\nFrom the Rust team", form.name))
        .unwrap();

    let existing_user = sqlx::query_scalar::<_, i32>(
    "SELECT id FROM users WHERE email = $1"
)
    .bind(&form.email)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(ErrorInternalServerError)?;

    if existing_user.is_some() {
        return Ok(HttpResponse::Conflict().body("Email already registered"));
    }

    if form.password.is_empty() {
        return Ok(HttpResponse::BadRequest().body("Password is required"));
    }

      // Hash password
    let password_hash = hash(&form.password, DEFAULT_COST)
        .map_err(|_| ErrorInternalServerError("Password hashing failed"))?;

     // Insert new user

   let new_user: (i32,) = sqlx::query_as(
    "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id"
)
    .bind(&form.name)
    .bind(&form.email)
    .bind(&password_hash)
    .fetch_one(pool.get_ref())
    .await
    .map_err(ErrorInternalServerError)?;

    let new_user_id = new_user.0;

    let creds = Credentials::new(
        "ekoiasuanetop@gmail.com".to_string(),
        "skabqfjdtoaqaopi".to_string(),
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
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
<body>
    <div class="container message-container">
        <h1>Registration Successful!</h1>
        <p>Registration saved and email sent!</p>
        <a href="/login" class="button">Login</a>
    </div>
</body>
</html>"#
    );

    match mailer.send(&email) {
        Ok(_) => Ok(HttpResponse::Ok().content_type("text/html").body(response_body)),
        Err(_) => Ok(HttpResponse::InternalServerError().body("Failed to send email")),
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
    let users = sqlx::query_as::<_, User>("SELECT id, name, email, created_at FROM users")
        .fetch_all(pool.get_ref())
        .await
        .unwrap();

    let mut ctx = tera::Context::new();
    ctx.insert("users", &users);

    let rendered = tmpl.render("users.html", &ctx).unwrap();
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
    let user = sqlx::query_as::<_, User>("SELECT id, name, email, created_at FROM users WHERE id = $1")
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

    let user = sqlx::query_as::<_, User>("SELECT id, name, email, created_at FROM users WHERE id = $1")
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
}

// HANDLE EDIT FORM SUBMISSION
async fn update_user_name(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    form: web::Form<EditForm>,
) -> impl Responder {
    let user_id = path.into_inner();

    let result = sqlx::query(
    "UPDATE users SET name = $1 WHERE id = $2"
)
    .bind(&form.name)
    .bind(user_id)
    .execute(pool.get_ref())
    .await;
    
    match result {
        Ok(_) => HttpResponse::Ok().body("Name updated successfully!"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed: {}", e)),
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
        .append_header(("Location", "/profile"))
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
    let user = sqlx::query_as::<_, User>("SELECT id, name, email, created_at FROM users WHERE id = $1")
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





#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Could not connect to database");

    let tera = Tera::new("static/**/*html")
        .expect("Failed to initialize Tera templates");

    // Create Redis store BEFORE HttpServer::new
    let redis_store = RedisSessionStore::new("redis://127.0.0.1:6379")
        .await
        .expect("Failed to connect to Redis");
    
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
                SessionMiddleware::new(
                    redis_store.clone(),
                    key.clone(),
                )
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
            .route("/users/{id}/edit", web::post().to(update_user_name))

            // Login
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login))

            


            // Static files
            .service(profile)
            .service(fs::Files::new("/", "./static").index_file("index.html"))
            

    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}