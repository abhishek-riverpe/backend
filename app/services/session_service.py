from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from prisma import Prisma
from app.utils.enums import SessionStatusEnum, LoginMethodEnum
from app.core.config import settings


class SessionService:

    SESSION_EXPIRY_DAYS = 7  # Sessions expire after 7 days (matches refresh token expiry)

    def __init__(self, prisma: Prisma):
        self.prisma = prisma

    async def create_session(
        self,
        entity_id: str,
        session_token: str,
        login_method: LoginMethodEnum = LoginMethodEnum.EMAIL_PASSWORD,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None,
        location_info: Optional[Dict[str, Any]] = None,
        client=None,
    ) -> Dict[str, Any]:
            """
            Create a login session.
            
            Args:
                entity_id: The entity ID
                session_token: The session token
                login_method: The login method used
                ip_address: Optional IP address
                user_agent: Optional user agent string
                device_info: Optional device information dict
                location_info: Optional location information dict
                client: Optional Prisma client (for transactions). If None, creates its own transaction.
            
            Returns:
                Dict with session id, expires_at, and is_suspicious flag
            """
            expires_at = datetime.now(timezone.utc) + timedelta(days=self.SESSION_EXPIRY_DAYS)
            
            device_data = device_info or {}
            device_type = device_data.get('device_type')
            device_name = device_data.get('device_name')
            os_name = device_data.get('os_name')
            os_version = device_data.get('os_version')
            browser_name = device_data.get('browser_name')
            browser_version = device_data.get('browser_version')
            app_version = device_data.get('app_version')
            
            location_data = location_info or {}
            country = location_data.get('country')
            city = location_data.get('city')
            latitude = location_data.get('latitude')
            longitude = location_data.get('longitude')
            
            is_suspicious = await self._check_suspicious_login(
                entity_id, ip_address, country
            )
            
            # If client is provided (for transactions), use it directly
            # Otherwise, create our own transaction for atomicity
            if client is not None:
                await self._enforce_concurrent_limit_with_client(client, entity_id)
                session = await client.login_sessions.create(
                    data={
                        "entity_id": entity_id,
                        "session_token": session_token,
                        "login_method": login_method,
                        "status": SessionStatusEnum.ACTIVE,
                        "ip_address": ip_address,
                        "user_agent": user_agent,
                        "device_type": device_type,
                        "device_name": device_name,
                        "os_name": os_name,
                        "os_version": os_version,
                        "browser_name": browser_name,
                        "browser_version": browser_version,
                        "app_version": app_version,
                        "country": country,
                        "city": city,
                        "latitude": latitude,
                        "longitude": longitude,
                        "expires_at": expires_at,
                        "is_suspicious": is_suspicious,
                    }
                )
            else:
                # Enforce concurrent limit and create session atomically in a transaction
                async with self.prisma.tx() as tx:
                    await self._enforce_concurrent_limit_with_client(tx, entity_id)

                    session = await tx.login_sessions.create(
                        data={
                            "entity_id": entity_id,
                            "session_token": session_token,
                            "login_method": login_method,
                            "status": SessionStatusEnum.ACTIVE,
                            "ip_address": ip_address,
                            "user_agent": user_agent,
                            "device_type": device_type,
                            "device_name": device_name,
                            "os_name": os_name,
                            "os_version": os_version,
                            "browser_name": browser_name,
                            "browser_version": browser_version,
                            "app_version": app_version,
                            "country": country,
                            "city": city,
                            "latitude": latitude,
                            "longitude": longitude,
                            "expires_at": expires_at,
                            "is_suspicious": is_suspicious,
                        }
                    )
            
            return {
                "id": session.id,
                "expires_at": expires_at.isoformat(),
                "is_suspicious": is_suspicious,
            }

    async def _enforce_concurrent_limit(self, entity_id: str) -> None:
        """Enforce concurrent session limit using the default prisma client."""
        await self._enforce_concurrent_limit_with_client(self.prisma, entity_id)
    
    async def _enforce_concurrent_limit_with_client(self, client, entity_id: str) -> None:
        """Enforce concurrent session limit using the provided client (supports transactions)."""
        try:
            max_sessions = settings.max_active_sessions
            if max_sessions is None or max_sessions <= 0:
                return

            active = await client.login_sessions.find_many(
                where={
                    "entity_id": entity_id,
                    "status": SessionStatusEnum.ACTIVE,
                },
                order={"login_at": "asc"},
            )

            if active and len(active) >= max_sessions:
                to_evict = len(active) - (max_sessions - 1)
                to_evict = max(1, to_evict)
                old_ids = [s.id for s in active[:to_evict]]
                await client.login_sessions.update_many(
                    where={"id": {"in": old_ids}},
                    data={"status": SessionStatusEnum.REVOKED},
                )
        except Exception:
            pass

    async def update_activity(self, session_token: str) -> Optional[bool]:
        try:
            now = datetime.now(timezone.utc)
            session = await self.prisma.login_sessions.find_unique(
                where={"session_token": session_token}
            )
            if not session:
                return None

            timeout = timedelta(minutes=settings.inactivity_timeout_minutes)
            last_activity = session.last_activity_at or session.login_at or now
            if last_activity and last_activity.tzinfo is None:
                last_activity = last_activity.replace(tzinfo=timezone.utc)
            if now - last_activity > timeout:
                await self.prisma.login_sessions.update(
                    where={"session_token": session_token},
                    data={"status": SessionStatusEnum.EXPIRED}
                )
                return False

            await self.prisma.login_sessions.update(
                where={"session_token": session_token},
                data={"last_activity_at": now}
            )
            return True
        except Exception:
            return None

    async def enforce_and_update_activity(self, session_token: str) -> Optional[bool]:
        return await self.update_activity(session_token)

    async def logout_session(self, session_token: str) -> bool:
        try:
            await self.prisma.login_sessions.update(
                where={"session_token": session_token},
                data={
                    "status": SessionStatusEnum.LOGGED_OUT,
                    "logout_at": datetime.now(timezone.utc),
                }
            )
            return True
        except Exception:
            return False

    async def revoke_session(self, session_id: str) -> bool:
        try:
            await self.prisma.login_sessions.update(
                where={"id": session_id},
                data={
                    "status": SessionStatusEnum.REVOKED,
                    "logout_at": datetime.now(timezone.utc),
                }
            )
            return True
        except Exception:
            return False

    async def get_active_sessions(self, entity_id: str) -> List[Dict[str, Any]]:
        try:
            sessions = await self.prisma.login_sessions.find_many(
                where={
                    "entity_id": entity_id,
                    "status": SessionStatusEnum.ACTIVE,
                    "expires_at": {"gt": datetime.now(timezone.utc)},
                },
                order={"login_at": "desc"}
            )
            
            return [
                {
                    "id": s.id,
                    "device_type": s.device_type,
                    "device_name": s.device_name,
                    "os_name": s.os_name,
                    "browser_name": s.browser_name,
                    "ip_address": s.ip_address,
                    "country": s.country,
                    "city": s.city,
                    "login_at": s.login_at.isoformat() if s.login_at else None,
                    "last_activity_at": s.last_activity_at.isoformat() if s.last_activity_at else None,
                    "is_suspicious": s.is_suspicious,
                }
                for s in sessions
            ]
        except Exception:
            return []

    async def get_session_history(
        self, 
        entity_id: str, 
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        try:
            sessions = await self.prisma.login_sessions.find_many(
                where={"entity_id": entity_id},
                order={"login_at": "desc"},
                take=limit
            )
            
            return [
                {
                    "id": s.id,
                    "status": s.status,
                    "login_method": s.login_method,
                    "device_info": f"{s.device_name or s.device_type or 'Unknown'} - {s.os_name or 'Unknown OS'}",
                    "location": f"{s.city or 'Unknown'}, {s.country or 'Unknown'}",
                    "ip_address": s.ip_address,
                    "login_at": s.login_at.isoformat() if s.login_at else None,
                    "logout_at": s.logout_at.isoformat() if s.logout_at else None,
                    "is_suspicious": s.is_suspicious,
                }
                for s in sessions
            ]
        except Exception:
            return []

    async def cleanup_expired_sessions(self) -> int:
        try:
            result = await self.prisma.login_sessions.update_many(
                where={
                    "status": SessionStatusEnum.ACTIVE,
                    "expires_at": {"lt": datetime.now(timezone.utc)},
                },
                data={"status": SessionStatusEnum.EXPIRED}
            )
            
            return result
        except Exception:
            return 0

    async def revoke_all_sessions(self, entity_id: str, except_token: Optional[str] = None, client=None) -> int:
        """
        Revoke all active sessions for an entity.
        
        Args:
            entity_id: The entity ID
            except_token: Optional session token to exclude from revocation
            client: Optional Prisma client (for transactions). If None, uses self.prisma.
        
        Returns:
            Number of sessions revoked
        """
        try:
            prisma_client = client if client is not None else self.prisma
            
            where_clause: Dict[str, Any] = {
                "entity_id": entity_id,
                "status": SessionStatusEnum.ACTIVE,
            }
            
            if except_token:
                where_clause["session_token"] = {"not": except_token}
            
            result = await prisma_client.login_sessions.update_many(
                where=where_clause,
                data={
                    "status": SessionStatusEnum.REVOKED,
                    "logout_at": datetime.now(timezone.utc),
                }
            )
            
            return result
        except Exception:
            return 0

    async def _check_suspicious_login(
        self,
        entity_id: str,
        ip_address: Optional[str],
        country: Optional[str]
    ) -> bool:
        try:
            recent_sessions = await self.prisma.login_sessions.find_many(
                where={
                    "entity_id": entity_id,
                    "status": SessionStatusEnum.ACTIVE,
                },
                order={"login_at": "desc"},
                take=10
            )
            
            if not recent_sessions:
                return False
            
            if country:
                recent_countries = [s.country for s in recent_sessions if s.country]
                if recent_countries and country not in recent_countries:
                    return True
            
            if ip_address:
                recent_ips = [s.ip_address for s in recent_sessions[:5] if s.ip_address]
                if recent_ips and ip_address not in recent_ips:
                    latest_login = recent_sessions[0].login_at
                    if latest_login and (datetime.now(timezone.utc) - latest_login).total_seconds() < 300:
                        return True
            
            return False
            
        except Exception:
            return False

