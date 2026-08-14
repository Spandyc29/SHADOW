from typing import Optional
from supabase import create_client, Client, ClientOptions
from config import SUPABASE_URL, SUPABASE_KEY

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_supabase_client(access_token: Optional[str] = None) -> Client:
    """
    Returns a request-scoped Supabase client initialized with the user's JWT access_token.
    If access_token is None, returns the standard backend anon client.
    """
    if access_token:
        return create_client(
            SUPABASE_URL,
            SUPABASE_KEY,
            options=ClientOptions(headers={"Authorization": f"Bearer {access_token}"})
        )
    return supabase