GraphQL is a query language for APIs.

* `graphQLmap` - [GitHub](https://github.com/swisskyrepo/GraphQLmap)

    Parse a GraphQL endpoint and extract data from it using introspection queries.

    ```bash
    # Dump names with introspection
    dump_via_introspection
    
    # Make a query
    {name(id: 0){id, value}}

    # Check if there is something in the first 30 ids
    {name(id: GRAPHQL_INCREMENT_10){id, value}}
    ```
