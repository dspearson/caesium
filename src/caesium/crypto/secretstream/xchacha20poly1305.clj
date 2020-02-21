(ns caesium.crypto.secretstream.xchacha20poly1305
  "Bindings for stream encryption"
  (:require [caesium.binding :as b]
            [caesium.crypto.scalarmult :as s]
            [caesium.byte-bufs :as bb])
  (:import [java.nio ByteBuffer]))

(b/defconsts [abytes
              headerbytes
              keybytes
              messagebytes-max
              tag-message
              tag-push
              tag-rekey
              tag-final
              statebytes])
