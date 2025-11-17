"""
Session Management Service

Tracks and manages user login sessions for security and analytics.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from prisma import Prisma
from prisma.enums import SessionStatusEnum, LoginMethodEnum
from app.core.config import settings

logger = logging.getLogger(__name__)


class SessionService:
    """Service for managing login sessions"""

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
    ) -> Dict[str, Any]:
        """
        Create a new login session
        
        Args:
            entity_id: User entity ID
            session_token: JWT token or session ID
            login_method: How user logged in
            ip_address: IP address of login
            user_agent: User agent string
            device_info: Device details (type, name, OS, browser, etc.)
            location_info: Location details (country, city, lat, long)
            
        Returns:
            Created session data
        """
        try:
            expires_at = datetime.now() + timedelta(days=self.SESSION_EXPIRY_DAYS)
            
            # Extract device info
            device_data = device_info or {}
            device_type = device_data.get('device_type')
            device_name = device_data.get('device_name')
            os_name = device_data.get('os_name')
            os_version = device_data.get('os_version')
            browser_name = device_data.get('browser_name')
            browser_version = device_data.get('browser_version')
            app_version = device_data.get('app_version')
            
            # Extract location info
            location_data = location_info or {}
            country = location_data.get('country')
            city = location_data.get('city')
            latitude = location_data.get('latitude')
            longitude = location_data.get('longitude')
            
            # Check for suspicious login
            is_suspicious = await self._check_suspicious_login(
                entity_id, ip_address, country
            )
            
            # Enforce concurrent session limit (evict oldest if at/over limit)
            await self._enforce_concurrent_limit(entity_id)

            session = await self.prisma.login_sessions.create(
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
            
            logger.info(f"[SESSION] Created session {session.id} for entity {entity_id}")
            
            return {
                "id": session.id,
                "expires_at": expires_at.isoformat(),
                "is_suspicious": is_suspicious,
            }
            
        except Exception as e:
            logger.error(f"[SESSION] Error creating session: {str(e)}", exc_info=True)
            raise

    async def _enforce_concurrent_limit(self, entity_id: str) -> None:
        """Ensure active sessions do not exceed configured max; evict oldest sessions if needed."""
        try:
            max_sessions = settings.max_active_sessions
            if max_sessions is None or max_sessions <= 0:
                return

            active = await self.prisma.login_sessions.find_many(
                where={
                    "entity_id": entity_id,
                    "status": SessionStatusEnum.ACTIVE,
                },
                order={"login_at": "asc"},
            )

            if active and len(active) >= max_sessions:
                # Evict as many as needed to make room for the new session
                to_evict = len(active) - (max_sessions - 1)
                to_evict = max(1, to_evict)
                old_ids = [s.id for s in active[:to_evict]]
                await self.prisma.login_sessions.update_many(
                    where={"id": {"in": old_ids}},
                    data={"status": SessionStatusEnum.REVOKED},
                )
                logger.info(f"[SESSION] Evicted {len(old_ids)} oldest sessions to enforce limit for entity {entity_id}")
        except Exception as e:
            logger.warning(f"[SESSION] Error enforcing concurrent limit: {str(e)}")

    async def update_activity(self, session_token: str) -> Optional[bool]:
        """
        Update last activity timestamp for a session
        
        Args:
            session_token: Session token to update
            
        Returns:
            True if updated successfully
        """
        try:
            now = datetime.now(timezone.utc)
            session = await self.prisma.login_sessions.find_unique(
                where={"session_token": session_token}
            )
            if not session:
                return None

            # Enforce inactivity timeout
            timeout = timedelta(minutes=settings.inactivity_timeout_minutes)
            last_activity = session.last_activity_at or session.login_at or now
            # Ensure both operands are timezone-aware in UTC
            if last_activity and last_activity.tzinfo is None:
                last_activity = last_activity.replace(tzinfo=timezone.utc)
            if now - last_activity > timeout:
                await self.prisma.login_sessions.update(
                    where={"session_token": session_token},
                    data={"status": SessionStatusEnum.EXPIRED}
                )
                try:
                    logger.info(
                        "[SESSION] Expired due to inactivity (timeout=%s min, last_activity=%s)",
                        settings.inactivity_timeout_minutes,
                        last_activity.isoformat() if last_activity else "unknown",
                    )
                except Exception:
                    pass
                return False

            await self.prisma.login_sessions.update(
                where={"session_token": session_token},
                data={"last_activity_at": now}
            )
            return True
        except Exception as e:
            logger.warning(f"[SESSION] Error updating activity: {str(e)}")
            return None

    async def enforce_and_update_activity(self, session_token: str) -> Optional[bool]:
        """
        Enforce inactivity timeout and update activity if still valid.
        Returns True if session is active after enforcement.
        """
        return await self.update_activity(session_token)

    async def logout_session(self, session_token: str) -> bool:
        """
        Logout a session (mark as logged out)
        
        Args:
            session_token: Session token to logout
            
        Returns:
            True if logged out successfully
        """
        try:
            await self.prisma.login_sessions.update(
                where={"session_token": session_token},
                data={
                    "status": SessionStatusEnum.LOGGED_OUT,
                    "logout_at": datetime.now(),
                }
            )
            logger.info(f"[SESSION] Logged out session with token {session_token}")
            return True
        except Exception as e:
            logger.error(f"[SESSION] Error logging out session: {str(e)}")
            return False

    async def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session (for security purposes)
        
        Args:
            session_id: Session ID to revoke
            
        Returns:
            True if revoked successfully
        """
        try:
            await self.prisma.login_sessions.update(
                where={"id": session_id},
                data={
                    "status": SessionStatusEnum.REVOKED,
                    "logout_at": datetime.now(timezone.utc),
                }
            )
            logger.info(f"[SESSION] Revoked session {session_id}")
            return True
        except Exception as e:
            logger.error(f"[SESSION] Error revoking session: {str(e)}")
            return False

    async def get_active_sessions(self, entity_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user
        
        Args:
            entity_id: User entity ID
            
        Returns:
            List of active sessions
        """
        try:
            sessions = await self.prisma.login_sessions.find_many(
                where={
                    "entity_id": entity_id,
                    "status": SessionStatusEnum.ACTIVE,
                    "expires_at": {"gt": datetime.now()},
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
        except Exception as e:
            logger.error(f"[SESSION] Error getting active sessions: {str(e)}")
            return []

    async def get_session_history(
        self, 
        entity_id: str, 
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get session history for a user
        
        Args:
            entity_id: User entity ID
            limit: Maximum number of sessions to return
            
        Returns:
            List of session history
        """
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
        except Exception as e:
            logger.error(f"[SESSION] Error getting session history: {str(e)}")
            return []

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions (background task)
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            result = await self.prisma.login_sessions.update_many(
                where={
                    "status": SessionStatusEnum.ACTIVE,
                    "expires_at": {"lt": datetime.now()},
                },
                data={"status": SessionStatusEnum.EXPIRED}
            )
            
            logger.info(f"[SESSION] Marked {result} expired sessions")
            return result
        except Exception as e:
            logger.error(f"[SESSION] Error cleaning up sessions: {str(e)}")
            return 0

    async def revoke_all_sessions(self, entity_id: str, except_token: Optional[str] = None) -> int:
        """
        Revoke all sessions for a user (e.g., when password changes)
        
        Args:
            entity_id: User entity ID
            except_token: Optional token to keep active (current session)
            
        Returns:
            Number of sessions revoked
        """
        try:
            where_clause: Dict[str, Any] = {
                "entity_id": entity_id,
                "status": SessionStatusEnum.ACTIVE,
            }
            
            if except_token:
                where_clause["session_token"] = {"not": except_token}
            
            result = await self.prisma.login_sessions.update_many(
                where=where_clause,
                data={
                    "status": SessionStatusEnum.REVOKED,
                    "logout_at": datetime.now(timezone.utc),
                }
            )
            
            logger.info(f"[SESSION] Revoked {result} sessions for entity {entity_id}")
            return result
        except Exception as e:
            logger.error(f"[SESSION] Error revoking all sessions: {str(e)}")
            return 0

    async def _check_suspicious_login(
        self,
        entity_id: str,
        ip_address: Optional[str],
        country: Optional[str]
    ) -> bool:
        """
        Check if a login is suspicious based on patterns
        
        Args:
            entity_id: User entity ID
            ip_address: IP address of login
            country: Country of login
            
        Returns:
            True if login seems suspicious
        """
        try:
            # Get recent successful logins
            recent_sessions = await self.prisma.login_sessions.find_many(
                where={
                    "entity_id": entity_id,
                    "status": SessionStatusEnum.ACTIVE,
                },
                order={"login_at": "desc"},
                take=10
            )
            
            if not recent_sessions:
                return False  # First login, not suspicious
            
            # Check for country mismatch
            if country:
                recent_countries = [s.country for s in recent_sessions if s.country]
                if recent_countries and country not in recent_countries:
                    logger.warning(f"[SESSION] Suspicious: New country {country} for entity {entity_id}")
                    return True
            
            # Check for rapid logins from different IPs
            if ip_address:
                recent_ips = [s.ip_address for s in recent_sessions[:5] if s.ip_address]
                if recent_ips and ip_address not in recent_ips:
                    # New IP within last 5 logins might be suspicious
                    latest_login = recent_sessions[0].login_at
                    if latest_login and (datetime.now() - latest_login).total_seconds() < 300:  # 5 minutes
                        logger.warning(f"[SESSION] Suspicious: Rapid login from new IP {ip_address}")
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"[SESSION] Error checking suspicious login: {str(e)}")
            return False

