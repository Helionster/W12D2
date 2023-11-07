class User < ApplicationRecord
  before_validation :ensure_session_token

  has_secure_password
  validates :username, :email, :session_token, presence: true, uniqueness: true 
  validates :username, length: { in: 3..30 }
  validates :email, length: { in: 3..225 }
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :username, format: { without: URI::MailTo::EMAIL_REGEXP, message:  "can't be an email" }
  validates :password, length: { in: 6..255 }, allow_nil: true

  def self.find_by_credentials(credential, password)
    user = nil;
    if (credential.match(URI::MailTo::EMAIL_REGEXP)) 
      user = User.find_by(email: credential)
    else 
      user = User.find_by(username: credential)
    end

    if user&.authenticate(password)
      return user
    else 
      nil
    end

    nil
  end

  def reset_session_token!
    self.session_token = generate_unique_session_token
    self.save!
    self.session_token
  end

  private
  def generate_unique_session_token
    loop do 
      token ||= SecureRandom.base64
      return token if !User.exists?(session_token: token)
    end
  end

  def ensure_session_token
    self.session_token ||= generate_unique_session_token
  end
end