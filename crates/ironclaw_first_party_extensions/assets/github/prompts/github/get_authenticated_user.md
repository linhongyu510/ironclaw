Use `github.get_authenticated_user` to identify the GitHub user authenticated by the configured token.

Call this capability for questions like "who am I on GitHub?", "which GitHub account is connected?", before making claims about the authenticated GitHub login, or before using an `author`, `assignee`, or `involves` filter for requests about "my" GitHub resources.

Do not infer the authenticated login from repository owners returned by `github.list_repos`; `/user/repos` can include repositories owned by organizations that the authenticated user can access.

This capability reads from the GitHub API through host HTTP egress and requires a configured GitHub product-auth account.
