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
}

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

    let existing_user = sqlx::query!(
        "SELECT id FROM users WHERE email = $1",
        form.email
    )
    .fetch_optional(pool.get_ref())
    .await
    .map_err(ErrorInternalServerError)?;

    if existing_user.is_some() {
        return Ok(HttpResponse::Conflict().body("Email already registered"));
    }

    sqlx::query!(
        "INSERT INTO users (name, email) VALUES ($1, $2)",
        form.name,
        form.email
    )
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


async fn list_users(pool: web::Data<sqlx::PgPool>) -> Result<HttpResponse, Error> {
    let users = sqlx::query_as::<_, User>(
        "SELECT id, name, email, created_at FROM users ORDER BY id DESC"
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(ErrorInternalServerError)?;

    let mut rows = String::new();
    for user in users {
        rows.push_str(&format!(
        "<tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td><a href=\"/users/{}\">View Profile</a></td>
        </tr>",
            user.id, user.name, user.email, user.created_at, user.id));
    }

    let template = std::fs::read_to_string("./static/users.html")
        .map_err(|_| ErrorInternalServerError("Failed to load HTML file"))?;

    let html = template.replace("{{users}}", &rows);

    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

pub async fn view_user(
    pool: web::Data<PgPool>,
    tmpl: web::Data<Tera>,
    path: web::Path<i32>,
) -> impl Responder {
    let user_id = path.into_inner();

    let user_result = sqlx::query_as::<_, User>(
        "SELECT id, name, email, created_at FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await;

    match user_result {
        Ok(user) => {
            let mut ctx = Context::new();
            ctx.insert("user", &user);

            match tmpl.render("profile.html", &ctx) {
                Ok(rendered) => HttpResponse::Ok()
                    .content_type("text/html")
                    .body(rendered),
                Err(err) => HttpResponse::InternalServerError()
                    .body(format!("Template error: {}", err)),
            }
        }
        Err(err) => HttpResponse::NotFound()
            .body(format!("User not found: {}", err)),
    }
}

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

async fn update_user_name(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    form: web::Form<EditForm>,
) -> impl Responder {
    let user_id = path.into_inner();

    let result = sqlx::query!(
        "UPDATE users SET name = $1 WHERE id = $2",
        form.name,
        user_id
    )
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("Name updated successfully!"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed: {}", e)),
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

HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(pool.clone()))
        .app_data(web::Data::new(tera.clone()))

        // Form submission
        .route("/submit", web::post().to(submit_form))

        // List users
        .route("/users", web::get().to(list_users))

        // View user profile
        .route("/users/{id}", web::get().to(view_user))

        // Edit user (GET + POST)
        .route("/users/{id}/edit", web::get().to(edit_user_form))
        .route("/users/{id}/edit", web::post().to(update_user_name))

        // Static files MUST NOT be mounted at "/"
        .service(fs::Files::new("/static", "./static"))
})

.bind(("127.0.0.1", 8080))?
.run()
.await

}
