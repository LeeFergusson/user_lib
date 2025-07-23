use std::process::exit;

use argon2::{
  Argon2, PasswordHash, PasswordVerifier,
  password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};

use serde::{Deserialize, Serialize};

use crate::RoleId;

// -- User ID Structure --------------------------------------------
/// Represents a user's ID
#[derive(
  Debug,
  Copy,
  Clone,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Hash,
  Serialize,
  Deserialize,
)]
pub struct UserId(uuid::Uuid);

impl Default for UserId {
  fn default() -> Self {
    UserId(uuid::Uuid::nil())
  }
}

impl std::fmt::Display for UserId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

impl UserId {
  /// Creates a new user ID.
  ///
  /// # Returns
  ///
  /// * `Self` - The new user ID.
  pub fn new() -> Self {
    UserId(uuid::Uuid::new_v4())
  }
}

impl From<String> for UserId {
  fn from(value: String) -> Self {
    UserId(uuid::Uuid::parse_str(&value).unwrap_or_default())
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRole {
  user_id: UserId,
  role_id: RoleId,
}

impl UserRole {
  /// Creates a new user role.
  ///
  /// # Arguments
  ///
  /// * `user` - The user associated with the role.
  /// * `role` - The role to assign to the user.
  ///
  /// # Returns
  ///
  /// * `Self` - The new user role.
  pub fn new(user_id: UserId, role_id: RoleId) -> Self {
    UserRole { user_id, role_id }
  }

  pub fn user_id(&self) -> &UserId {
    &self.user_id
  }

  pub fn role_id(&self) -> &RoleId {
    &self.role_id
  }
}

// -- UserName Structure -------------------------------------------
/// Represents a user's name
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserName(std::rc::Rc<str>);

impl UserName {
  /// Creates a new user name.
  ///
  /// # Arguments
  ///
  /// * `name` - The name of the user.
  ///
  /// # Returns
  ///
  /// * `Self` - The new user name.
  pub fn new(name: &str) -> Self {
    UserName(std::rc::Rc::from(name))
  }
}

// -- Implement Display for UserName.
impl std::fmt::Display for UserName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UserError {
  PasswordMismatch,
  InvalidPassword,
}

impl std::error::Error for UserError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    None
  }

  fn cause(&self) -> Option<&dyn std::error::Error> {
    self.source()
  }
}

impl std::fmt::Display for UserError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      UserError::PasswordMismatch => write!(f, "Password mismatch"),
      UserError::InvalidPassword => write!(f, "Invalid password"),
    }
  }
}

// -- User Structure -----------------------------------------------
/// User represents a user in the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
  id: UserId,
  name: UserName,
  password: UserPassword,
  created_at: chrono::DateTime<chrono::Local>,
  updated_at: Option<chrono::DateTime<chrono::Local>>,
  roles: Vec<UserRole>,
}

impl User {
  /// Creates a new user with the given name.
  ///
  /// # Arguments
  ///
  /// * `name` - The name of the user.
  ///
  /// # Returns
  ///
  /// * `Self` - The new user.
  pub fn new(
    name: UserName,
    password: UserPassword,
  ) -> Result<Self, Box<dyn std::error::Error>> {
    let user = User {
      id: UserId::new(),
      name,
      password,
      created_at: chrono::Local::now(),
      updated_at: None,
      roles: Vec::new(),
    };
    Ok(user)
  }

  pub fn password(&self) -> &UserPassword {
    &self.password
  }

  pub fn verify_password(&self, password: &str) -> bool {
    self.password.verify(password).is_ok()
  }

  /// Adds a role to the user.
  ///
  /// # Arguments
  ///
  /// * `role` - The role to add to the user.
  ///
  /// # Returns
  ///
  /// * `Self` - The updated user.
  pub fn with_role(mut self, role_id: RoleId) -> Self {
    self.roles.push(UserRole {
      user_id: self.id,
      role_id,
    });
    self
  }

  /// Adds a role to the user.
  ///
  /// # Arguments
  ///
  /// * `role` - The role to add to the user.
  ///
  /// # Returns
  ///
  /// * `&mut Self` - A mutable reference to the user.
  pub fn add_role(&mut self, role_id: RoleId) -> &mut Self {
    self.roles.push(UserRole {
      user_id: self.id,
      role_id,
    });
    self
  }

  /// Removes a role from the user.
  ///
  /// # Arguments
  ///
  /// * `role` - The role to remove from the user.
  ///
  /// # Returns
  ///
  /// * `&mut Self` - A mutable reference to the user.
  pub fn remove_role(&mut self, role_id: RoleId) -> &mut Self {
    self.roles.retain(|r| r.role_id != role_id);
    self
  }

  /// Returns the ID of the user.
  ///
  /// # Returns
  ///
  /// * `UserId` - The ID of the user.
  pub fn id(&self) -> UserId {
    self.id
  }

  /// Returns the name of the user.
  ///
  /// # Returns
  ///
  /// * `&UserName` - The name of the user.
  pub fn name(&self) -> &UserName {
    &self.name
  }

  /// Returns the creation date of the user.
  ///
  /// # Returns
  ///
  /// * `&chrono::DateTime<chrono::Local>` - The creation date of the user.
  pub fn created_at(&self) -> &chrono::DateTime<chrono::Local> {
    &self.created_at
  }

  /// Returns the update date of the user.
  ///
  /// # Returns
  ///
  /// * `Option<&chrono::DateTime<chrono::Local>>` - The update date of the user.
  pub fn updated_at(&self) -> Option<&chrono::DateTime<chrono::Local>> {
    self.updated_at.as_ref()
  }

  /// Returns the roles of the user.
  ///
  /// # Returns
  ///
  /// * `&Vec<Rc<UserRole>>` - The roles of the user.
  pub fn roles(&self) -> &Vec<UserRole> {
    &self.roles
  }
}

// -- UserPassword Structure ---------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPassword(String);

impl UserPassword {
  /// Creates a new user password.
  ///
  /// # Arguments
  ///
  /// * `password` - The password of the user.
  ///
  /// # Returns
  ///
  /// * `Self` - The new user password.
  pub fn new(
    password: &str,
    confirm_password: &str,
  ) -> Result<Self, UserError> {
    if password != confirm_password {
      return Err(UserError::PasswordMismatch);
    }
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
      Ok(hash) => Self(hash.to_string()),
      Err(_err) => exit(1),
    };
    Ok(password_hash)
  }

  pub fn verify(
    &self,
    password: &str,
  ) -> Result<bool, Box<dyn std::error::Error>> {
    let argon2 = Argon2::default();
    match PasswordHash::new(&self.0) {
      Ok(parsed_hash) => {
        let result = argon2
          .verify_password(password.as_bytes(), &parsed_hash)
          .is_ok();
        Ok(result)
      }

      Err(_) => Ok(false),
    }
  }
}

// -- Tests ------------------------------------------------------------------
#[cfg(test)]
mod tests {
  use crate::role::{Role, RoleName};

  use super::*;

  #[test]
  fn create_new_user() {
    let user = User::new(
      UserName::new("bob"),
      UserPassword::new("password", "password").unwrap(),
    )
    .unwrap();
    assert_eq!(user.name(), &UserName::new("bob"));
    assert_eq!(user.updated_at(), None);
  }

  #[test]
  fn create_new_user_with_role() -> Result<(), Box<dyn std::error::Error>> {
    let role = Role::new(RoleName::try_from("admin")?);

    let user = User::new(
      UserName::new("bob"),
      UserPassword::new("password", "password")?,
    )?
    .with_role(role.id());
    assert_eq!(user.name(), &UserName::new("bob"));
    assert_eq!(user.updated_at(), None);
    assert_eq!(user.roles().len(), 1);
    Ok(())
  }

  #[test]
  fn remove_role_from_user() -> Result<(), Box<dyn std::error::Error>> {
    let role = Role::new(RoleName::try_from("admin")?);
    let mut user = User::new(
      UserName::new("bob"),
      UserPassword::new("password", "password")?,
    )?
    .with_role(role.id());
    let user = user.remove_role(role.id());
    assert_eq!(user.roles().len(), 0);
    Ok(())
  }
}
