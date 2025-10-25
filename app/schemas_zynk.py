from pydantic import BaseModel

class PermanentAddress(BaseModel):
    addressLine1: str
    addressLine2: str | None = None
    locality: str | None = None
    city: str
    state: str
    country: str
    postalCode: str

class CreateZynkEntityIn(BaseModel):
    type: str
    firstName: str
    lastName: str
    email: str
    phoneNumberPrefix: str
    phoneNumber: str
    nationality: str
    dateOfBirth: str
    permanentAddress: PermanentAddress
