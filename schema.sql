Table Users {
  email varchar(255) [primary key]
  username varchar(255) [not null, unique]
  password_hash varchar(255) [not null]
  phone_number varchar(50)
  is_activated boolean [not null, default : False]
  mfa_secret varchar(32) 
  is_mfa_enabled boolean [default: False]
  role Role [default: Role.regular]
}

Table ActivationTokens {
  email varchar(255) [primary key]
  activation_token varchar(255) [not null]
  expires_at datetime [not null]
}

Table PasswordResetToken {
  email varchar(255) [primary key, not null]
  reset_token varchar(255) [not null]
  expires_at datetime [not null]
}

Table RefreshToken {
  email varchar(255) [primary key, not null]
  jti varchar(64) [unique, not null]
  expires_at datetime [default: False, not null]
  revoked boolean [not null]
}

Table Post {
  id varchar(255) [primary key, not null]
  content bytes(5120) 
  title varchar(255) [not null]
  description varchar(1024)
  author_username varchar(255) [not null, unique]
}

Table Comment {
  id varchar(255) [primary key, not null]
  content varchar(1024) [not null]
  author_username varchar(255) [not null]
  post_id varchar(255) [not null]
}

enum Role {
  regular
  admin
}

Ref: Users.email - ActivationTokens.email
Ref: Users.email - PasswordResetToken.email
Ref: Users.email - RefreshToken.email
Ref: Users.username < Post.author_username
Ref: Users.username < Comment.author_username
Ref: Comment.post_id > Post.id




