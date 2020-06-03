# cveapi-go

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)

Golang client for [cveapi](https://cveapi.com/) API

## Usage

```go
package main

import (
    "fmt"
    "github.com/viiftw/cveapi-go"
)

func main() {
  client := cveapi.NewClient()

  // get cve data
  cveID := "CVE-2019-9956"
  cveData, err := client.GetCVEData(cveID)
  if err != nil {
    fmt.Println(err)
  } else {
    fmt.Println(cveData.Cve.CVEDataMeta.ID, cveData.Cve.CVEDataMeta.Assigner)
  }
  // => CVE-2019-9956 cve@mitre.org
}
```
