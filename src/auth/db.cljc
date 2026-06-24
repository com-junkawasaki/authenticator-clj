(ns auth.db
  "The account vault as a Datomic-API store.

  Backed by langchain.db — a pure-.cljc, dependency-free, Datomic-shaped EAV
  engine (create-conn / transact! / q / pull / entity). Accounts are entities;
  lookups are Datalog. `:account/id` is a `:db.unique/identity` attribute, so
  re-adding the same issuer+name upserts instead of duplicating (the behaviour
  you want when re-scanning a QR code)."
  (:require [langchain.db :as d]
            [clojure.string :as str]))

(def schema
  {:account/id        {:db/unique :db.unique/identity}
   :account/issuer    {}
   :account/name      {}
   :account/secret    {}
   :account/type      {}
   :account/algorithm {}
   :account/digits    {}
   :account/period    {}
   :account/counter   {}})

(defn account-id
  "Canonical identity for an account: `issuer:name`, or just `name`."
  [{:account/keys [issuer name]}]
  (if (seq issuer) (str issuer ":" name) (str name)))

(defn empty-conn [] (d/create-conn schema))

(defn ->state
  "Serialises the whole connection to plain EDN data (for the vault file)."
  [conn] @conn)

(defn state->conn
  "Rebuilds a connection from previously-serialised EDN state, refreshing the
  schema so code changes take effect on reload."
  [state]
  (atom (assoc-in (or state {:db (:db @(empty-conn)) :log []})
                  [:db :schema] schema)))

;; ───────────────────────── writes ─────────────────────────

(defn put!
  "Upserts an account (a map of :account/* keys, minus :account/id which is
  derived). Returns the tx report."
  [conn account]
  (let [acct (->> account
                  (remove (fn [[_ v]] (nil? v)))
                  (into {}))]
    (d/transact! conn [(assoc acct :account/id (account-id acct))])))

(defn remove!
  "Removes the account with the given canonical id. Returns true if it existed."
  [conn id]
  (if-let [eid (d/entid (d/db conn) [:account/id id])]
    (do (d/transact! conn [[:db/retractEntity eid]]) true)
    false))

(defn bump-counter!
  "Increments the HOTP moving factor for `id` and returns the new counter."
  [conn id]
  (let [n (inc (or (:account/counter (d/pull (d/db conn) [:account/counter] [:account/id id])) 0))]
    (d/transact! conn [{:account/id id :account/counter n}])
    n))

;; ───────────────────────── reads (Datalog) ─────────────────────────

(defn all
  "All accounts, sorted by issuer then name."
  [conn]
  (let [dbv (d/db conn)]
    (->> (d/q '[:find [?id ...] :where [?e :account/id ?id]] dbv)
         (map #(d/pull dbv '[*] [:account/id %]))
         (sort-by (juxt #(str/lower-case (or (:account/issuer %) ""))
                        #(str/lower-case (or (:account/name %) "")))))))

(defn get-by-id [conn id]
  (d/pull (d/db conn) '[*] [:account/id id]))

(defn search
  "Case-insensitive substring match over id / issuer / name. `q` blank → all."
  [conn q]
  (if (str/blank? q)
    (all conn)
    (let [needle (str/lower-case q)]
      (filter (fn [a]
                (some #(and % (str/includes? (str/lower-case (str %)) needle))
                      [(:account/id a) (:account/issuer a) (:account/name a)]))
              (all conn)))))
