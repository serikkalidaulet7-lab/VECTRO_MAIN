"""Route and OpenAPI regressions for the Users authentication surface."""

import pytest


@pytest.fixture
def api_app(monkeypatch: pytest.MonkeyPatch):
    """Import the application with valid test configuration."""
    monkeypatch.setenv("DEBUG", "false")
    from app.main import app

    return app


def test_auth_routes_are_registered_once_with_a_safe_logout_schema(api_app) -> None:
    """Authentication routes and OpenAPI expose only the approved logout contract."""
    routers = [getattr(route, "original_router", None) for route in api_app.routes]
    routes = [
        (route.path, method, route)
        for router in routers
        if router is not None
        for route in router.routes
        for method in getattr(route, "methods", set())
    ]
    expected = [
        ("/users", "POST"),
        ("/auth/register", "POST"),
        ("/auth/login", "POST"),
        ("/auth/refresh", "POST"),
        ("/auth/logout", "POST"),
        ("/auth/me", "GET"),
    ]
    for path, method in expected:
        assert (
            sum(
                route_path == path and route_method == method
                for route_path, route_method, _ in routes
            )
            == 1
        )
    assert not any(
        path in {"/auth/logout-all", "/auth/sessions", "/auth/revoke", "/auth/introspect"}
        for path, _, _ in routes
    )

    schema = api_app.openapi()
    logout = schema["paths"]["/auth/logout"]["post"]
    assert logout["responses"]["204"].get("content") in (None, {})
    request_schema = logout["requestBody"]["content"]["application/json"]["schema"]
    request_ref = request_schema["$ref"].split("/")[-1]
    properties = schema["components"]["schemas"][request_ref]["properties"]
    assert set(properties) == {"refresh_token"}
    assert not {"token_hash", "session_id", "family_id", "password", "password_hash"} & set(
        properties
    )
