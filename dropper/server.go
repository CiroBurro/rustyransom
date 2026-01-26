package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

const Port = 1337

func handler(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/" {
		http.ServeFile(w, r, "static/404.html")
		return
	}

	//gpuUsage, gpuTemp := getGpuStats()
	data := model{
		Uptime:   getUptime(),
		CpuUsage: getCpuUsage(),
		CpuTemp:  getCpuTemp(),
		GpuUsage: 0,
		GpuTemp:  0,
		MemUsage: getMemoryUsage(),
	}

	t, err := template.ParseFiles("static/index.html")
	if err != nil {
		log.Println("Template parsing error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)

	if err != nil {
		log.Println("Template execution error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func runServer() {

	// Serve static files (CSS, JS, Images) from the "static" directory
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", handler)
	addr := fmt.Sprintf(":%d", Port)
	log.Printf("Server listening on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
