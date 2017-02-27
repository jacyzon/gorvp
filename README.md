# GoRvp

## Compile

Pre requirement
- Go 1.6 or higher version
- Glide package manager

```bash
glide install
cd example
go build -o gorvp_ex
```

## Usage

```bash
cd example
./gorvp_ex -c ../fixtures/config.yml -p 3000
```

`-c` specify the config file, `-p` specify the port that GoRvp will be listen.

## Migration

The RSA key-pair is generated at the first time when GoRvp started,
copy these files to the new machine or otherwise, the previously generated token will be invalid.

## API document

Please head to https://io.jacyzon.com/gorvp.
