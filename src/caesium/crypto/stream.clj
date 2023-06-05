(ns caesium.crypto.stream
  (:require [caesium.binding :as b]))

(b/defconsts [chacha20-keybytes
              chacha20-noncebytes
              chacha20-ietf-keybytes
              chacha20-ietf-noncebytes])
