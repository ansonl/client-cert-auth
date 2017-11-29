package main

import (
	"net/http"
	"fmt"
)

func logoutClient(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	user := r.Form.Get("user")
	token := r.Form.Get("token")

	fmt.Println(user);
	fmt.Println(token);

	w.Header().Set("Access-Control-Allow-Origin", "*")
	if (checkAuthTokenForUser(user, token) == true) {
		removeAllAuthTokensForUser(user)
	} else {
		fmt.Fprintf(w, "w");
	}

	fmt.Fprintf(w, "Goodbye")
}
