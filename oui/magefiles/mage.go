package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"
)

const (
	ouiURL  = "https://standards-oui.ieee.org/oui/oui.csv"
	ouiCSV  = "oui.csv"
	ouiData = "data.go"
)

// Build builds the package
func Build() {
	mg.Deps(mg.F(generate, ouiCSV, ouiData))
}

func download() error {
	stale, err := target.Path(ouiCSV, "magefiles/mage.go", "magefiles/gen.go")
	if err != nil {
		return err
	}

	if !stale {
		return nil
	}

	log.Printf("downloading %q", ouiURL)
	req, err := http.NewRequest(http.MethodGet, ouiURL, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mage-oui-parser")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: status code=%s", resp.Status)
	}

	fout, err := os.Create("oui.csv")
	if err != nil {
		return err
	}
	defer fout.Close()

	_, err = io.Copy(fout, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func Clean() error {
	for _, file := range []string{ouiCSV} {
		if err := sh.Rm(file); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	os.Setenv("MAGEFILE_ENABLE_COLOR", "1")
	os.Setenv("MAGEFILE_VERBOSE", "1")
}
