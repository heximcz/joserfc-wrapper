### The `joserfc-wrapper` library simplifies the use of JWT and automates the management of signature keys.

#### Install
`pip install joserfc-wrapper`

#### Reason

The main purpose of this wrapper is to simplify the management of signature keys for generating JWT tokens using the [joserfc]((https://github.com/authlib/joserfc)) library and adhering to RFC standards. It offers two options for managing signature keys: securely storing generated keys in [HashiCorp Vault](https://github.com/hvac/hvac) or storing them on the filesystem. Additionally, it facilitates the use of JWT tokens in projects.

#### Need a custom solution for storing keys? We've got you covered.

If necessary, a custom object can be created to manage signing keys, including storing them in a database. However, this custom class must be a subclass of the parent [AbstractKeyStorage](https://github.com/heximcz/joserfc-wrapper/blob/main/joserfc_wrapper/AbstractKeyStorage.py) abstract class to implement the necessary methods.

#### Using a Virtual Environment for `joserfc_wrapper`
We recommend running joserfc_wrapper in a virtual environment for the following reasons:

- Project Isolation: A virtual environment isolates this project's dependencies from the rest of your system. This allows you to work with specific library versions required for joserfc_wrapper without the risk of conflicts with other projects.

- Virtual environments make it easy to manage and track project dependencies, which is crucial for ensuring reproducibility and consistency in development.

- Using a virtual environment ensures seamless integration and deployment, guaranteeing consistent operation across all development and production environments.

To create a virtual environment for joserfc_wrapper, follow these steps:
```bash
python -m venv .venv
source .venv/bin/activate
pip install joserfc_wrapper
```
By following these guidelines, you can ensure a smooth and problem-free experience when working with `joserfc_wrapper`.

#### [Documentation](https://github.com/heximcz/joserfc-wrapper/blob/main/docs/index.md)

### License

[joserfc](https://github.com/authlib/joserfc?tab=readme-ov-file#license) (BSD-3)

[joserfc_wrapper](./LICENSE) (MIT)

#### Contributions to the development of this library are welcome, ideally in the form of a pull request.
