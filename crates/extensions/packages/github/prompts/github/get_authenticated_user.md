Use `github.get_authenticated_user` to identify the GitHub user authenticated by the configured token.

Call this capability for questions like "who am I on GitHub?", "which GitHub account is connected?", or before making claims that require the authenticated account's concrete login.

Do not call this capability only to expand the current user for issue or pull-request search. The `author`, `assignee`, and `involves` filters accept `@me` directly, and query-only relationships such as `user-review-requested:@me` do too.

Do not infer the authenticated login from repository owners returned by `github.list_repos`; `/user/repos` can include repositories owned by organizations that the authenticated user can access.

This capability reads from the GitHub API through host HTTP egress and requires a configured GitHub product-auth account.
