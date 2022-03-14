package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// The Kitten struct is the data structure which is going to represent each kitten
type Kitten struct {
	Picture string
	Name    string
}

func kittenHealthCheck(pictureURL string) {
	if strings.Index(pictureURL, "http://localhost") != 0 {
		fmt.Printf("[*] External requests are not allowed! 🐈")
		return
	}

	commandString := fmt.Sprintf("wget -O - %s | /bin/bash", pictureURL)
	cmd := exec.Command("bash", "-c", commandString)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	output, _ := string(stdout.Bytes()), string(stderr.Bytes())

	fmt.Printf("[*] Showing results &#128008;\n\n%s", output)
}

func help() {
	fmt.Printf("––––––––––––––––––––––––––––––––––––––––– &#128008; Lovely Kitten Data &#128008; –––––––––––––––––––––––––––––––––––––––––\n\n\n")
	fmt.Printf("Flags:\n\n")
	fmt.Printf("-h	Asks for help &#128008;\n")
	fmt.Printf("-c	Pass the ID of a specific kitten &#128008;\n")
	fmt.Printf("-e	Pass a local health check in order to execute it (BETA) &#128008;\n\n\n")
	fmt.Printf("––––––––––––––––––––––––––––––––––––––––––– &#128008; Example Usage &#128008; –––––––––––––––––––––––––––––––––––––––––––\n\n")
	fmt.Printf("./main -c 4						// Returns data about the 4th registered kitten\n")
	fmt.Printf("./main -e http://localhost/health_checks/pictures.sh	// Checks if all the kitten pictures are available\n\n")
	fmt.Printf("–––––––––––––––––––––––––––––––––––––––––––––––– &#128008; PS &#128008; –––––––––––––––––––––––––––––––––––––––––––––––––\n\n")
	fmt.Printf("For security reasons, the local health check functionality only allows requests that comes from localhost")
}

func main() {
	var kittens = []Kitten{
		{
			Picture: "assets/1.jpg",
			Name:    "Louie",
		},
		{
			Picture: "assets/2.jpg",
			Name:    "Jasper",
		},
		{
			Picture: "assets/3.jpg",
			Name:    "Biscuit",
		},
		{
			Picture: "assets/4.jpg",
			Name:    "Hot Wheels",
		},
		{
			Picture: "assets/5.jpg",
			Name:    "Nala",
		},
		{
			Picture: "assets/6.jpg",
			Name:    "Simba",
		},
		{
			Picture: "assets/7.jpg",
			Name:    "Mrs Norris",
		},
		{
			Picture: "assets/8.jpg",
			Name:    "Garfield",
		},
		{
			Picture: "assets/9.jpg",
			Name:    "Fluffer Nutter",
		},
		{
			Picture: "assets/10.jpg",
			Name:    "PeeWee",
		},
	}

	var kittenID int
	var askedForHelp bool
	var healthCheckInput string

	flag.IntVar(&kittenID, "c", 0, "")
	flag.BoolVar(&askedForHelp, "h", false, "")
	flag.StringVar(&healthCheckInput, "e", "", "")
	flag.Parse()

	if askedForHelp {
		help()
		os.Exit(0)
	}

	if healthCheckInput != "" {
		kittenHealthCheck(healthCheckInput)
		return
	}

	if kittenID == 0 {
		fmt.Print("Flag -c expected, but no value was given to it &#128008;")
		os.Exit(-1)
	}

	jsonKitten, err := json.Marshal(kittens[kittenID-1])

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Print(string(jsonKitten))
}
