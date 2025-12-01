use actix_files as fs;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use actix_web::error::ErrorInternalServerError;
use actix_web::Error;
use tera::{Tera, Context};
use actix_session::Session;
use actix_session::{SessionMiddleware, storage::RedisSessionStore};
use actix_web::cookie::Key;





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
    created_at: chrono::NaiveDateTime,
    role: String,
}

// HANDLE FORM SUBMISSION
async fn submit_form(
    form: web::Form<FormData>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, Error> {
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

   sqlx::query(
    "INSERT INTO users (name, email) VALUES ($1, $2)"
)
    .bind(&form.name)
    .bind(&form.email)
    .execute(pool.get_ref())
    .await
    .map_err(ErrorInternalServerError)?;

    let creds = Credentials::new(
        "ekoiasuanetop@gmail.com".to_string(),
        "skabqfjdtoaqaopi".to_string(),
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => Ok(HttpResponse::Ok().body("Registration saved and email sent!")),
        Err(_) => Ok(HttpResponse::InternalServerError().body("Failed to send email")),
    }
}

// LIST USERS - ADMIN ONLY
async fn list_users(
    session: Session,
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>,
) -> impl Responder {

    // 1. Check login
    let role: String = match session.get("role").unwrap_or(None) {
        Some(r) => r,
        None => return HttpResponse::Unauthorized().body("Please log in"),
    };

    // 2. Allow admin only
    if role != "admin" {
        return HttpResponse::Forbidden().body("Access denied: Admins only");
    }

    // 3. Admin can view all users
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
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
    session: Session,
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>,
    path: web::Path<i32>,
) -> impl Responder {
    let requested_id = path.into_inner();

    // 1. Check logged-in user
    let user_id: i32 = match session.get("user_id").unwrap_or(None) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().body("Please log in"),
    };

    let role: String = session.get("role").unwrap().unwrap();

    // 2. Access rules:
    // Admin can view anyone
    // Users can only view THEIR OWN profile
    if role != "admin" && user_id != requested_id {
        return HttpResponse::Forbidden().body("You can only view your own profile");
    }

    // Fetch the user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
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

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
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
pub async fn download_users_csv(pool: web::Data<PgPool>) -> impl Responder {
    // Fetch all users
   let users = sqlx::query_as::<_, User>("SELECT id, name, email, created_at, role FROM users")
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
            "{},{:?},{:?},{:?}\n",
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
    
    let secret_key = Key::generate();

    HttpServer::new(move || {
        App::new()
           .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(tera.clone()))
            
            .wrap(
                SessionMiddleware::new(
                    redis_store.clone(),
                    secret_key.clone(),
                )
            )

            // Form submission
            .route("/submit", web::post().to(submit_form))

            // List users
            .route("/users", web::get().to(list_users))

            // View user profile
            .route("/users/{id}", web::get().to(view_user))

            // Edit user (GET + POST)
            .route("/users/{id}/edit", web::get().to(edit_user_form))
            .route("/users/{id}/edit", web::post().to(update_user_name))

            //Download users list
            .route("/users/download", web::get().to(download_users_csv))

            // Static files
            .service(fs::Files::new("/", "./static").index_file("index.html"))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}