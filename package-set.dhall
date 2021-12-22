let upstream = https://github.com/Bochslertech/package-set/releases/download/v0.1/package-set.dhall
let Package = { name : Text, version : Text, repo : Text, dependencies : List Text }
let additions = [
  { name = "crypto"
  , repo = "https://github.com/Bochslertech/crypto"
  , version = "v0.1"
  , dependencies = [ "base"]
  }
] : List Package
in  upstream # additions