module HPass where

import Data.Text
import Options.Applicative
import Data.Elocrypt qualified as Elocrypt
import System.Random (getStdGen)
import Data.Aeson qualified as A
import Network.Wreq qualified as W
import Network.HTTP.Types qualified as HTTP
import Control.Lens qualified as L
import System.Directory
import System.IO

graphqlUrl :: String
graphqlUrl = "http://127.0.0.1:8080/v1/graphql"

authApiUrl :: String
authApiUrl = "http://127.0.0.1:5000"

data User = User
  { _uUserName :: Text,
    _uUserPassword :: Text
  } deriving (Show)

instance A.ToJSON User where
  toJSON User{..} =
    A.object ["username" A..= _uUserName, "password" A..= _uUserPassword]

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
  Login user -> login user
  Logout -> print "Not implemented yet"
  Generate genPassOpts -> print =<< generateRandomPassword genPassOpts

data LoginApiResponse
  = LARSuccess Text
  | LARFailure Text

instance A.FromJSON LoginApiResponse where
  parseJSON = A.withObject "Object" $ \o ->
    (LARSuccess <$> o A..: "session_token")
    <|> (LARFailure <$> o A..: "error")

data SignupApiResponse
  = SARSuccess Text
  | SARFailure Text

instance A.FromJSON SignupApiResponse where
  parseJSON = A.withObject "Object" $ \o ->
    (SARSuccess <$> o A..: "message")
    <|> (SARFailure <$> o A..: "error")

mkPost :: (A.ToJSON a, A.FromJSON b) => String -> a -> [HTTP.Header] -> IO (Maybe b)
mkPost url body headers = do
  r <- W.post url $ A.toJSON body
  pure $ A.decode' $ r L.^. W.responseBody

signup :: User -> IO ()
signup user = do
  apiRes <- mkPost (authApiUrl <> "/signup") user []
  case apiRes of
    Nothing -> print "API Nothing error"
    Just (SARSuccess msg) -> print msg
    Just (SARFailure msg) -> print msg

hpassConfigFile :: IO FilePath
hpassConfigFile = do
  homeDir <- getHomeDirectory
  pure $ homeDir <> "/.hpass"

storeTokenLocal :: Text -> IO ()
storeTokenLocal token = do
  hpassFile <- hpassConfigFile
  writeFile hpassFile $ unpack token

login :: User -> IO ()
login user = do
  apiRes <- mkPost (authApiUrl <> "/login") user []
  case apiRes of
    Nothing -> print "API Nothing error"
    Just (LARFailure msg) -> print msg
    Just (LARSuccess token) -> do
      storeTokenLocal token
      print "signin succussful"

logout :: IO ()
logout = do
  hpassFile <- hpassConfigFile
  withFile hpassFile ReadWriteMode $ \hdl -> do
    tok <- hGetContents hdl
    if tok == "" then print "No active sessions found"
      else do
      undefined

generateRandomPassword :: GenPasswordOptions -> IO String
generateRandomPassword GenPasswordOptions{..} = do
  randomGen <- getStdGen
  let genOptions = Elocrypt.GenOptions _gpoCapitals _gpoDigits _gpoSpecials
  pure $ Elocrypt.newPassword _gpoLength genOptions randomGen
