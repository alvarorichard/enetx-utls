# About this repository

This is a copy of `github.com/enetx/utls` at **v1.0.10**, kept because that
repository is no longer on GitHub (it answered 404 from 2026-11-19, and why is
not known). It exists so that [GoAnime](https://github.com/alvarorichard/GoAnime)
can keep building from a repository that is there.

- The first commit is the module zip of v1.0.10 exactly as the Go module proxy served it
  (checksum database: `github.com/enetx/utls v1.0.10 h1:QDaiO2enhiL8DsxYe+Omf7TkQktLi2Zp+bAiZqniv9g=`). `git diff HEAD~1` shows everything changed since.
- The only changes are the Go import paths and `go.mod` module paths, from
  `github.com/enetx/*` to `github.com/alvarorichard/enetx-*`, and this file. The
  upstream CI in `.github/` was left out.
- There is no upstream history, no issue tracker and no promise of new features. The
  license is the one the code came with (see `LICENSE`).
