mod role;
mod user;

pub use role::{Role, RoleId, RoleName};
pub use user::{User, UserError, UserId, UserName, UserPassword, UserRole};

pub fn add(left: u64, right: u64) -> u64 {
  left + right
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let result = add(2, 2);
    assert_eq!(result, 4);
  }
}
