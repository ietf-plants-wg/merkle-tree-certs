package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s COMMAND [ARGS...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Available commands:\n")
		fmt.Fprintf(os.Stderr, "  generate - Generate test MTC certificates\n")
	}

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(0)
	}

	switch cmd := flag.Arg(0); cmd {
	case "generate":
		if err := generate(flag.Args()[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating certificates: %s\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized command %q\n", cmd)
		flag.Usage()
		os.Exit(2)
	}
}
