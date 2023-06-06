(ns caesium.crypto.secretstream.xchacha20poly1305
  "Bindings for stream encryption"
  (:require [caesium.binding :as b]
            [caesium.crypto.scalarmult :as s]
            [caesium.byte-bufs :as bb]
            [caesium.crypto.stream :as stream])
  (:import [java.nio ByteBuffer]
           [jnr.ffi.annotations Pinned]
           [jnr.ffi Pointer Struct]))

(b/defconsts [abytes headerbytes keybytes messagebytes-max tag-message tag-push tag-rekey tag-final])

(def ^{:const true} tagbytes "The size of a secretstream state tag, in bytes." 8)

(def statebytes (+ stream/chacha20-keybytes stream/chacha20-noncebytes tagbytes))


(defn create-pointer [^ByteBuffer buffer]
  (let [runtime (jnr.ffi.Runtime/getSystemRuntime)]
    (Pointer/wrap runtime buffer)))

(defn create-null-pointer []
  (let [runtime (jnr.ffi.Runtime/getSystemRuntime)]
    (Pointer/wrap runtime (long 0))))

(defn keygen-to-buf!
  "Generate a random, secret key to encrypt a stream, and stores it in k."
  [k]
  (b/call! keygen k))

(defn ^ByteBuffer keygen!
  "Create a secret key for use in stream encryption."
  []
  (let [k (bb/alloc keybytes)]
     (keygen-to-buf! k)
     ^java.nio.ByteBuffer k))

(defn stream!
  "Create a secretstream."
  []
  (let [state-buf (bb/alloc statebytes)
        state     (create-pointer state-buf)
        key       (keygen!)
        header    (bb/alloc headerbytes)]
    (.crypto_secretstream_xchacha20poly1305_init_push
      b/sodium
      ^jnr.ffi.Pointer state
      header
      key)
    {:state         state-buf
     :state-pointer state
     :header        header
     :k             key}))

;; (defn encrypt
;;   [message {:keys [state]}]
;;   (let [buflen (count message)
;;         buf (bb/alloc buflen)
;;         bufpointer (create-pointer buf)]
;;     (.crypto_secretstream_xchacha20poly1305_push
;;       b/sodium
;;       ^jnr.ffi.Pointer state
;;       ^jnr.ffi.Pointer bufpointer
;;       (create-null-pointer)
;;       (create-pointer (bb/->direct-byte-buf message))
;;       (count message)
;;       (create-null-pointer)
;;       0
;;       0)
;;     buf))
