from typing import List

from fastapi_camelcase import CamelModel
from pydantic import Field, EmailStr


class EnvelopeArgs(CamelModel):
    signer_email: str = EmailStr()
    signer_name: str = Field(min_length=4)


class EnvelopeUserContext(CamelModel):
    email = EmailStr()
    phone_number: str
    full_name: str
    role_name: str = 'signer'
    client_user_id: str
    tabs: List = []


class EnvelopeContext(CamelModel):
    roles: List[EnvelopeUserContext] = []
    template_id: str
    status: str = 'sent'