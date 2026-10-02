# Publish the project report

The report is `docs/index.html`; it needs no build step. The README's online
report link targets <https://yacndehfuli.github.io/MemTriage/>.

After reviewing and pushing the commit to `main`, set **Settings → Pages →
Build and deployment → Source** to **GitHub Actions**, then run the **Project
report** workflow (or let a subsequent docs push trigger it). The workflow
publishes `docs/`, including screenshots, report examples, and evidence JSON.
Pages was not configured when this change was prepared; the online link is
not live until that setup and deployment complete. No push or deployment was
performed as part of the local documentation commit.

The original root demos are tracked with Git LFS. The page's video players
use GitHub's `media.githubusercontent.com` endpoint, since GitHub Pages does
not resolve LFS pointers into media. The LFS objects must be uploaded by the
normal Git LFS pre-push hook. Do not replace or re-encode the recordings.

Local review: serve the repository root with any static HTTP server and open
`/docs/index.html`. To watch a recording before publishing, use the page's
**Local recording** link, or open the original root file directly. The HTML
also opens from disk; remote video playback requires the files on GitHub.

[GitHub Pages workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
