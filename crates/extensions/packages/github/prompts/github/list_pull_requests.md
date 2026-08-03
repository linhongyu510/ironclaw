Use `github.list_pull_requests` to list pull requests in one repository.

Use `head`, `base`, `sort`, and `direction` when the user asks for branch-filtered or ordered pull request lists.

Do not use this capability when the requested set depends on the authenticated user's relationship to a pull request; this endpoint has no author, assignee, involvement, or review-request filter. Use `github.search_issues_pull_requests` instead and match the relationship the user asked for: `author: "@me"`, `assignee: "@me"`, or `involves: "@me"`, or a focused `query` such as `user-review-requested:@me`. Do not equate every request about "my" pull requests with authorship.

The result keeps the GitHub list endpoint's top-level array and returns compact summaries with the pull request number, title, state/draft status, URL, author, labels, assignees and requested reviewers/teams, milestone, branches, and timestamps. Use `page` and `limit` to continue through results. For the body, mergeability, diff statistics, or other full detail on one result, call `github.get_pull_request` with its `pr_number`.

Use the exact JSON field names from this capability schema. If the user provides a GitHub URL, extract the owner and repo fields plus the schema-specific number, path, or ref key; for pull-request tools, use `pr_number`; for issue tools, use `issue_number`.

This capability reads from the GitHub API through host HTTP egress and requires a configured GitHub product-auth account.
