(ns caesium.crypto.secretstream.xchacha20poly1305
  "Bindings for stream encryption"
  (:require [caesium.binding :as b]
            [caesium.crypto.scalarmult :as s]
            [caesium.byte-bufs :as bb]
            [caesium.crypto.stream :as stream])
  (:import [java.nio ByteBuffer]
           [jnr.ffi.annotations Pinned]
           [jnr.ffi Pointer]))

(b/defconsts [abytes headerbytes keybytes messagebytes-max tag-message tag-push tag-rekey tag-final])

(def ^{:const true} tagbytes "The size of a secretstream state tag, in bytes." 8)

(def statebytes (+ stream/chacha20-keybytes stream/chacha20-noncebytes tagbytes))

(defn create-pointer [^ByteBuffer buffer]
  (let [runtime (jnr.ffi.Runtime/getSystemRuntime)]
    (Pointer/wrap runtime buffer)))

(defn keygen-to-buf!
  "Generate a random, secret key to encrypt a stream, and stores it in k."
  [k]
  (b/call! keygen k))

(defn keygen!
  "Create a secret key for use in stream encryption."
  []
  (let [k (bb/alloc keybytes)]
     (keygen-to-buf! k)
     k))

(defn stream!
  "Create a secretstream."
  []
  (let [state  (bb/alloc statebytes)
        sp     (create-pointer state)
        key    (keygen!)
        header (bb/alloc headerbytes)]
    (.crypto_secretstream_xchacha20poly1305_init_push
      sp header key)
    {:state  state
     :header header
     :k      key}))
