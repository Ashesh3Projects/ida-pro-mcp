import asyncio

import pytest

from _instance_support import FakeProvider, identity
from ida_pro_mcp.instance_contract import RoutingError, split_instance_uri
from ida_pro_mcp.instance_router import InstanceRouter


@pytest.mark.parametrize("uri", ["ida://idb/metadata", "ida://idb/metadata?instance_id=", "ida://idb/metadata?instance_id=" + "a"*16 + "&instance_id=" + "a"*16, "ida://idb/metadata?instance_id="+"a"*16+"&other=x"])
def test_resource_requires_one_valid_selector(uri):
    with pytest.raises(RoutingError):
        split_instance_uri(uri)


def test_resource_response_keeps_public_identity_and_encoded_name():
    async def scenario():
        p = FakeProvider([identity("A"), identity("B")])
        router = InstanceRouter(p)
        a, b = [r["instance_id"] for r in (await router.list_instances())["instances"]]
        for target in (a, b):
            uri = f"ida://struct/my%20struct?instance_id={target}"
            result = await router.read_resource(uri)
            assert result["contents"][0]["uri"] == uri
            assert p.calls[-1][2] == {"uri": "ida://struct/my%20struct"}
        await router.shutdown()
    asyncio.run(scenario())
