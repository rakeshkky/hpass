module HPass where

import Data.Text
import Options.Applicative
import Data.Elocrypt qualified as Elocrypt
import System.Random (getStdGen)

data User = User
  { _uUserName :: Text,
    _uUserPassword :: Text
  } deriving (Show)

parseUser :: Parser User
parseUser =
  User
  <$> strOption
      ( long "username" <>
        short 'u' <>
        help "HPass username"
      )
  <*> strOption
      ( long "password" <>
        short 'p' <>
        help "HPass password"
      )

data GenPasswordOptions = GenPasswordOptions
  { _gpoLength :: Int,
    _gpoCapitals :: Bool,
    _gpoDigits :: Bool,
    _gpoSpecials :: Bool
  } deriving (Show)

parsePasswordOptions :: Parser GenPasswordOptions
parsePasswordOptions =
  GenPasswordOptions
    <$> option auto
        ( long "length" <>
          short 'l' <>
          help "Length of the password" <>
          value 10 <>
          showDefault <>
          metavar "INT"
        )
    <*> switch
        ( long "capitals" <>
          short 'c' <>
          help "Generate with capital letters"
        )
    <*> switch
        ( long "digits" <>
          short 'd' <>
          help "Generate with numeric digits"
        )
    <*> switch
        ( long "special-chars" <>
          short 's' <>
          help "Generate with special characters"
        )

newtype Website = Website {getWebsite :: Text}
  deriving (Show)

parseWebsite :: Parser Website
parseWebsite =
  Website
  <$> strOption
      ( long "website" <>
        short 'w' <>
        help "Website"
      )

newtype Username = Username {getUsername :: Text}
  deriving (Show)

parseUsername :: Parser Username
parseUsername =
  Username
  <$> strOption
      ( long "username" <>
        short 'u' <>
        help "Username"
      )

newtype Password = Password {getPassword :: Text}
  deriving (Show)

parsePassword :: Parser Password
parsePassword =
  Password
  <$> strOption
      ( long "password" <>
        short 'p' <>
        help "Password"
      )

data Command
  = Signup User
  | Login User
  | Logout
  | Add Website Username Password
  | Remove Website Username
  | Get Website Username
  | List
  | Generate GenPasswordOptions
  deriving (Show)

parseCommand :: Parser Command
parseCommand =
  subparser
    ( command
        "signup"
        ( info
            (helper <*> (Signup <$> parseUser))
            ( progDesc "Signup for HPass")
        )
      <>
      command
        "login"
        ( info
            (helper <*> (Login <$> parseUser))
            ( progDesc "Login HPass")
        )
      <>
      command
        "logout"
        ( info
            (helper <*> pure Logout)
            ( progDesc "Logout HPass")
        )
      <>
      command
        "add"
        ( info
            (helper <*> (Add <$> parseWebsite <*> parseUsername <*> parsePassword))
            ( progDesc "Add a password to the store")
        )
      <>
      command
        "remove"
        ( info
            (helper <*> (Remove <$> parseWebsite <*> parseUsername))
            ( progDesc "Remove a password from the store")
        )
      <>
      command
        "get"
        ( info
            (helper <*> (Get <$> parseWebsite <*> parseUsername))
            ( progDesc "Retrieve a password from the store")
        )
      <>
      command
        "list"
        ( info
            (helper <*> pure List)
            ( progDesc "List all passwords")
        )
      <>
      command
        "generate"
        ( info
            (helper <*> (Generate <$> parsePasswordOptions))
            ( progDesc "Generate a random password")
        )
    )

getCommand :: IO Command
getCommand =
  execParser options
  where
    options = info (helper <*> parseCommand)
                   (fullDesc <> header "HPass: A CLI tool to manage passwords")

runCommand :: Command -> IO ()
runCommand = \case
  Signup user -> signup user
  Login user -> print "Not implemented yet"
  Logout -> print "Not implemented yet"
  Generate genPassOpts -> print =<< generateRandomPassword genPassOpts

signup :: User -> IO ()
signup = undefined

generateRandomPassword :: GenPasswordOptions -> IO String
generateRandomPassword GenPasswordOptions{..} = do
  randomGen <- getStdGen
  let genOptions = Elocrypt.GenOptions _gpoCapitals _gpoDigits _gpoSpecials
  pure $ Elocrypt.newPassword _gpoLength genOptions randomGen
