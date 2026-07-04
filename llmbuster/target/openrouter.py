from __future__ import annotations

from importlib.resources import files

import httpx
from pydantic import BaseModel

from llmbuster.target.profile import ProfileConfig, ProfileTarget

OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"

_RESOURCE_PACKAGE = "llmbuster.resources"
_MODEL_PLACEHOLDER = "__MODEL__"


class ModelInfo(BaseModel):
    id: str
    name: str | None = None
    context_length: int | None = None
    pricing: dict[str, str] | None = None


async def fetch_models(client: httpx.AsyncClient) -> list[ModelInfo]:
    response = await client.get(OPENROUTER_MODELS_URL)
    response.raise_for_status()
    data = response.json()
    models = data.get("data", []) if isinstance(data, dict) else data
    return [ModelInfo.model_validate(m) for m in models]


def load_openrouter_profile_template() -> dict[str, object]:
    yaml_text = (files(_RESOURCE_PACKAGE) / "openrouter.yaml").read_text(
        encoding="utf-8"
    )
    import yaml

    loaded = yaml.safe_load(yaml_text)
    if not isinstance(loaded, dict):
        raise TypeError("openrouter.yaml must be a mapping")
    return loaded


def build_profile(model_id: str) -> ProfileConfig:
    template = load_openrouter_profile_template()
    request = template.get("request", {})
    if not isinstance(request, dict):
        raise TypeError("openrouter.yaml request must be a mapping")
    body = request.get("body", "")
    if not isinstance(body, str):
        raise TypeError("openrouter.yaml request.body must be a string")
    request = {**request, "body": body.replace(_MODEL_PLACEHOLDER, model_id)}
    template = {**template, "request": request}
    return ProfileConfig.model_validate(template)


def build_target(model_id: str, client: httpx.AsyncClient | None = None) -> ProfileTarget:
    return ProfileTarget(build_profile(model_id), client=client)
