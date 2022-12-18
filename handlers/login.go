func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	token, err := auth.UserLogin(username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Write([]byte(token))
}
