module Main where

import HPass

main :: IO ()
main = getCommand >>= runCommand
