(ns auth.otp-test
  (:require [clojure.test :refer [deftest is testing]]
            [auth.otp :as otp]
            [auth.base32 :as base32]))

(def ^:private ascii (comp vec (partial map int) seq))

;; RFC 4226 §5.1 / Appendix D — secret = ASCII "12345678901234567890".
(def rfc4226-secret-b32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
(def rfc4226-codes
  ["755224" "287082" "359152" "969429" "338314"
   "254676" "287922" "162583" "399871" "520489"])

(deftest base32-decodes-rfc-secret
  (is (= (ascii "12345678901234567890")
         (base32/decode rfc4226-secret-b32)))
  (testing "case / spacing / padding tolerated"
    (is (= (base32/decode rfc4226-secret-b32)
           (base32/decode (str "gezd gnbv gy3t qojq " "GEZDGNBVGY3TQOJQ"))))))

(deftest base32-roundtrip
  (doseq [s ["MFRGG===" "JBSWY3DPEHPK3PXP" rfc4226-secret-b32]]
    (is (= (base32/decode s) (base32/decode (base32/encode (base32/decode s)))))))

(deftest hotp-rfc4226
  (let [secret (base32/decode rfc4226-secret-b32)]
    (doseq [[counter expected] (map-indexed vector rfc4226-codes)]
      (is (= expected (otp/hotp secret counter))
          (str "HOTP counter " counter)))))

;; RFC 6238 Appendix B — 8-digit codes, T0=0, step=30. Per-algorithm seeds.
(def totp-seeds
  {:sha1   (ascii "12345678901234567890")
   :sha256 (ascii "12345678901234567890123456789012")
   :sha512 (ascii "1234567890123456789012345678901234567890123456789012345678901234")})

(def totp-vectors
  ;; [unix-seconds {algo expected}]
  [[59          {:sha1 "94287082" :sha256 "46119246" :sha512 "90693936"}]
   [1111111109  {:sha1 "07081804" :sha256 "68084774" :sha512 "25091201"}]
   [1111111111  {:sha1 "14050471" :sha256 "67062674" :sha512 "99943326"}]
   [1234567890  {:sha1 "89005924" :sha256 "91819424" :sha512 "93441116"}]
   [2000000000  {:sha1 "69279037" :sha256 "90698825" :sha512 "38618901"}]
   [20000000000 {:sha1 "65353130" :sha256 "77737706" :sha512 "47863826"}]])

(deftest totp-rfc6238
  (doseq [[t expected] totp-vectors
          [algo code] expected]
    (is (= code (otp/totp (totp-seeds algo) t {:algorithm algo :digits 8}))
        (str "TOTP " (name algo) " @ " t))))

(deftest totp-defaults-6-digits
  ;; default 6-digit/SHA1 is the low 6 of the 8-digit SHA1 vector
  (is (= "287082" (otp/totp (totp-seeds :sha1) 59))))

(deftest remaining-seconds-counts-down
  (is (= 1  (otp/remaining-seconds 59 30)))   ; 59 mod 30 = 29 → 1 left
  (is (= 30 (otp/remaining-seconds 30 30)))   ; exact boundary
  (is (= 20 (otp/remaining-seconds 10 30))))

(deftest account-code-dispatch
  (let [totp-acct {:account/type :totp :account/secret rfc4226-secret-b32
                   :account/digits 8 :account/period 30 :account/algorithm :sha1}
        hotp-acct {:account/type :hotp :account/secret rfc4226-secret-b32
                   :account/counter 0 :account/digits 6 :account/algorithm :sha1}]
    (is (= "94287082" (otp/account-code totp-acct 59)))
    (is (= "755224"   (otp/account-code hotp-acct 0)))))
