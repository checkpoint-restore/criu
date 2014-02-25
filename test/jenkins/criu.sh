source `dirname $0`/criu-lib.sh &&
prep &&
bash test/zdtm.sh -C &&
true || fail

# Execute tests for each new commit
git rev-parse tested || ( git tag tested; exit )
for i in `git rev-list --reverse tested..HEAD`; do
    curl "http://localhost:8080/job/CRIU-by-id/buildWithParameters?token=d6edab71&TEST_COMMIT=$i" || exit 1
done
git tag -f tested
