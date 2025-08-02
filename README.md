# MakeMCP Testbed

Main purpose of this repository is to provide testbed artifacts for MakeMCP (see: https://github.com/t4cceptor/MakeMCP/).

## Quickstart

### OpenAPI Source
MakeMCP OpenAPI source enables creation of a MCP server from any OpenAPI (v3/3.1) specification.
Both servers (Python - FastAPI, and Golang - fuego) are providing simple OpenAPI specs which can be translated by MakeMCP into MCP tools and then used. They are fully functional in the sense that they are working APIs, with very limited functionality (only a single object is available with multiple endpoints.)
Purpose of those endpoints is not to provide any functionality, but only to demonstrate and test capabilities developed for MakeMCP.

#### Python - FastAPI
Requirements:
- Python installed (tested with 3.12)

Features JWT Bearer Token Authentication flow, which can be switched on and off using the provided .env.example file - see: `AUTH_ENABLED` flag

Uses port `8081` by default - see `fastapi_test_server/Makefile`

#### Go - fuego
Requirements:
- Go installed (tested with `1.24.1` on darwin)

Does currently only feature basic OpenAPI spec, also descriptions and content types are not refined.

Uses port `8120` by default - see `go_test_server/main.go - line 9`
