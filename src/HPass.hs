module HPass where

import Data.Text
import Data.Text.Encoding qualified as TE
import Data.ByteString.Lazy qualified as BL
import Options.Applicative
import Data.Elocrypt qualified as Elocrypt
import System.Random (getStdGen)
import Data.Aeson qualified as A
import Data.Aeson.Lens qualified as AL
import Network.Wreq qualified as W
import Network.HTTP.Types qualified as HTTP
import Control.Lens qualified as L
import System.Directory
import System.IO
import Control.Monad.Reader
import Text.RawString.QQ
import Data.HashMap.Strict qualified as HM
import Data.Maybe
import System.Exit

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
  | UserInfo
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
        "user-info"
        ( info
            (helper <*> pure UserInfo)
            ( progDesc "Get user info")
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
  UserInfo -> withToken userInfo
  Logout -> logout
  Add website username password -> withToken $ add website username password
  Remove website username -> withToken $ remove website username
  Get website username -> withToken $ get website username
  List -> withToken list
  Generate genPassOpts -> putStrLn =<< generateRandomPassword genPassOpts

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

mkPost :: (A.ToJSON a, A.FromJSON b, MonadIO m) => String -> a -> W.Options -> m (Maybe b)
mkPost url body opts = do
  r <- liftIO $ W.postWith opts url $ A.toJSON body
  pure $ A.decode' $ r L.^. W.responseBody

signup :: User -> IO ()
signup user = do
  apiRes <- mkPost (authApiUrl <> "/signup") user W.defaults
  case apiRes of
    Nothing -> putStrLn "API Nothing error"
    Just (SARSuccess msg) -> putStrLn $ unpack msg
    Just (SARFailure msg) -> putStrLn $ unpack msg

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
  apiRes <- mkPost (authApiUrl <> "/login") user W.defaults
  case apiRes of
    Nothing -> putStrLn "API Nothing error"
    Just (LARFailure msg) -> putStrLn $ unpack msg
    Just (LARSuccess token) -> do
      storeTokenLocal token
      putStrLn "signin succussful"

logout :: IO ()
logout = do
  hpassFile <- hpassConfigFile
  withFile hpassFile ReadWriteMode $ \hdl -> do
    hasTok <- not <$> hIsEOF hdl
    if hasTok then do
      hSetFileSize hdl 0
      putStrLn "Logout successful"
    else putStrLn "No active session found"

generateRandomPassword :: GenPasswordOptions -> IO String
generateRandomPassword GenPasswordOptions{..} = do
  randomGen <- getStdGen
  let genOptions = Elocrypt.GenOptions _gpoCapitals _gpoDigits _gpoSpecials
  pure $ Elocrypt.newPassword _gpoLength genOptions randomGen

type Token = Text

withToken :: ReaderT Token IO a -> IO a
withToken action = do
  hpassFile <- hpassConfigFile
  withFile hpassFile ReadMode $ \hdl -> do
    hasTok <- not <$> hIsEOF hdl
    if hasTok then do
      tok <- hGetContents hdl
      runReaderT action (pack tok)
    else do
      putStrLn "Not logged, please login again"
      exitFailure

data GraphQLRes
  = GQLSuccess A.Value
  | GQLErrors [A.Value]
  | GQLParseFailed

instance A.FromJSON GraphQLRes where
  parseJSON = A.withObject "Object" $ \o ->
    (GQLSuccess <$> o A..: "data") <|> (GQLErrors <$> o A..: "errors") <|> (pure GQLParseFailed)

data GraphQLQuery =
  GraphQLQuery
  { _gqqQuery :: Text
  , _gqqVariables :: HM.HashMap Text A.Value
  }

instance A.ToJSON GraphQLQuery where
  toJSON GraphQLQuery{..} =
    A.object ["query" A..= _gqqQuery, "variables" A..= _gqqVariables]

getAllPasswordsQuery :: Text
getAllPasswordsQuery = [r|
query {
  password{
    website
    username
  }
}
|]

insertPasswordQuery :: Text
insertPasswordQuery = [r|
mutation ($website: String, $username: String, $password: String) {
  insert_password_one(
    object: {website: $website, username: $username, password: $password}
  ){
    __typename
  }
}
|]

gqlUrl :: String
gqlUrl = "http://127.0.0.1:8080/v1/graphql"

runGraphQLQuery :: (MonadReader Token m, MonadIO m) => GraphQLQuery -> m GraphQLRes
runGraphQLQuery query = do
  tok <- ask
  let opts = W.defaults L.& W.auth L.?~ W.oauth2Bearer (TE.encodeUtf8 tok)
  r <- mkPost gqlUrl query opts
  case r of
    Nothing -> pure GQLParseFailed
    Just a -> pure a

list :: (MonadReader Token m, MonadIO m) => m ()
list = do
  res <- runGraphQLQuery (GraphQLQuery getAllPasswordsQuery mempty)
  liftIO $ case res of
    GQLParseFailed -> putStrLn "API response parsing failed"
    GQLSuccess v -> BL.putStr $ A.encode v
    GQLErrors _ -> putStrLn "GraphQL query failed"

add :: (MonadReader Token m, MonadIO m) => Website -> Username -> Password -> m ()
add Website{..} Username{..} Password{..} = do
  let variables = HM.fromList [ ("website",  A.String getWebsite),
                                ("username", A.String getUsername),
                                ("password", A.String getPassword)
                              ]
  res <- runGraphQLQuery (GraphQLQuery insertPasswordQuery variables)
  liftIO $ case res of
    GQLParseFailed -> putStrLn "Cannot add password, API parsing failed"
    GQLSuccess _ -> putStrLn "Password recorded"
    GQLErrors _ -> putStrLn "GraphQL query failure"

userInfoQuery :: Text
userInfoQuery = [r|
query {
  user{
    username
    passwords_aggregate{
      aggregate{
        count
      }
    }
  }
}
|]

userInfo :: (MonadReader Token m, MonadIO m) => m ()
userInfo = do
  res <- runGraphQLQuery (GraphQLQuery userInfoQuery mempty)
  liftIO $ case res of
    GQLParseFailed -> putStrLn "Fetching user info failed, API parsing failed"
    GQLSuccess v -> BL.putStr $ A.encode v
    GQLErrors _ -> putStrLn "GraphQL query failure"

removePasswordQuery :: Text
removePasswordQuery = [r|
mutation($website: String, $username: String) {
  delete_password(where: {website: {_eq: $website}, username: {_eq: $username}}){
    affected_rows
  }
}
|]

remove :: (MonadReader Token m, MonadIO m) => Website -> Username -> m ()
remove Website{..} Username{..} = do
  let variables = HM.fromList [ ("website", A.String getWebsite),
                                ("username", A.String getUsername)
                              ]
  res <- runGraphQLQuery (GraphQLQuery removePasswordQuery variables)
  liftIO $ case res of
    GQLParseFailed -> putStrLn "Cannot remove password, API parsing failed"
    GQLSuccess _ -> putStrLn "Password removed"
    GQLErrors _ -> putStrLn "GraphQL query failure"

getPasswordQuery :: Text
getPasswordQuery = [r|
query($website: String, $username: String) {
  password(where: {website: {_eq: $website}, username: {_eq: $username}}){
    password
  }
}
|]

get :: (MonadReader Token m, MonadIO m) => Website -> Username -> m ()
get Website{..} Username{..} = do
  let variables = HM.fromList [ ("website", A.String getWebsite),
                                ("username", A.String getUsername)
                              ]
  res <- runGraphQLQuery (GraphQLQuery getPasswordQuery variables)
  liftIO $ case res of
    GQLParseFailed -> putStrLn "Cannot get password, API parsing failed"
    GQLSuccess v -> BL.putStr $ A.encode v
    GQLErrors _ -> putStrLn "GraphQL query failure"
