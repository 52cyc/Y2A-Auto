import ast
import hashlib
import pathlib
import re
import secrets
import unittest


def _load_token_helpers(*names):
    app_path = pathlib.Path(__file__).resolve().parents[1] / "app.py"
    source = app_path.read_text(encoding="utf-8")
    module_ast = ast.parse(source, filename=str(app_path))
    requested = set(names)
    if "_verify_tgbot_api_token" in requested:
        requested.update({"_is_valid_tgbot_api_token_format", "_hash_tgbot_api_token"})

    selected = []
    for node in module_ast.body:
        if isinstance(node, ast.Assign):
            if any(
                isinstance(target, ast.Name)
                and target.id in {
                    "TG_BOT_API_TOKEN_PREFIX",
                    "TG_BOT_API_TOKEN_HASH_PREFIX",
                    "_TG_BOT_API_TOKEN_RANDOM_RE",
                }
                for target in node.targets
            ):
                selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in requested:
            selected.append(node)

    isolated_module = ast.Module(body=selected, type_ignores=[])
    namespace = {
        "hashlib": hashlib,
        "re": re,
        "secrets": secrets,
        "load_config": lambda: {},
    }
    exec(compile(isolated_module, str(app_path), "exec"), namespace)
    return [namespace[name] for name in names]


class TgbotTokenAuthTests(unittest.TestCase):
    def test_generated_token_has_expected_format_and_hash(self):
        generate_token, is_valid_format, hash_token = _load_token_helpers(
            "_generate_tgbot_api_token",
            "_is_valid_tgbot_api_token_format",
            "_hash_tgbot_api_token",
        )

        token = generate_token()
        token_hash = hash_token(token)

        self.assertTrue(token.startswith("y2a_tgbot_v1_"))
        self.assertTrue(is_valid_format(token))
        self.assertTrue(token_hash.startswith("sha256:"))
        self.assertNotIn(token, token_hash)

    def test_verify_compares_against_stored_hash(self):
        generate_token, hash_token, verify_token = _load_token_helpers(
            "_generate_tgbot_api_token",
            "_hash_tgbot_api_token",
            "_verify_tgbot_api_token",
        )

        token = generate_token()
        config = {"TG_BOT_API_TOKEN_HASH": hash_token(token)}

        self.assertTrue(verify_token(token, config))
        self.assertFalse(verify_token(token + "x", config))
        self.assertFalse(verify_token("not-a-y2a-token", config))
        self.assertFalse(verify_token(token, {"TG_BOT_API_TOKEN_HASH": ""}))

    def test_token_state_does_not_expose_secret(self):
        token_state, = _load_token_helpers("_tgbot_api_token_state")
        state = token_state({
            "TG_BOT_API_TOKEN_HASH": "sha256:" + "a" * 64,
            "TG_BOT_API_TOKEN_CREATED_AT": "2026-07-08 12:00:00",
            "TG_BOT_API_TOKEN_LAST4": "AbCd",
        })

        self.assertEqual(state, {
            "configured": True,
            "created_at": "2026-07-08 12:00:00",
            "last4": "AbCd",
        })


if __name__ == "__main__":
    unittest.main()
