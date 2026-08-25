from pydantic import BaseModel, ConfigDict, Field


class SubnetRequest(BaseModel):
    ip_cidr: str = Field(
        min_length=1,
        max_length=256,
        examples=["192.168.10.25/24"],
    )


class SubnetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    input: str
    ip_address: str
    version: int
    cidr: str
    prefix_length: int
    network: str
    subnet_mask: str
    wildcard_mask: str | None
    first_host: str
    last_host: str
    broadcast: str | None
    total_addresses: int
    usable_hosts: int
    assumed_prefix: bool


class SubnetCalculationResponse(SubnetResponse):
    investigation_id: int
