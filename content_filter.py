"""
Content Filter Module
Blocks access to specific categories of websites based on URL and content
"""

import re
import logging
from urllib.parse import urlparse

class ContentFilter:
    def __init__(self, config):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.logger = logging.getLogger(__name__)
        
        # Blocked categories with keywords
        self.blocked_categories = {
            'sports': [
                'football', 'soccer', 'basketball', 'tennis', 'cricket',
                'nfl', 'nba', 'fifa', 'espn', 'sport', 'match', 'league',
                'championship', 'tournament', 'goal', 'score', 'team'
            ],
            'gambling': [
                'casino', 'poker', 'betting', 'bet', 'gamble', 'lottery',
                'jackpot', 'slots', 'roulette', 'blackjack'
            ],
            'social_media': [
                'facebook', 'twitter', 'instagram', 'tiktok', 'snapchat',
                'linkedin', 'reddit', 'pinterest'
            ],
            'streaming': [
                'netflix', 'hulu', 'youtube', 'twitch', 'streaming',
                'video', 'movie', 'series'
            ],
            'adult': [
                'porn', 'xxx', 'adult', 'sex', 'nude', 'nsfw'
            ]
        }
        
        # Domain blacklist
        self.domain_blacklist = set(config.get('domain_blacklist', []))
        
        # Domain whitelist (always allowed)
        self.domain_whitelist = set(config.get('domain_whitelist', []))
        
        # Active categories (which categories to block)
        self.active_categories = set(config.get('active_categories', ['sports', 'gambling', 'adult']))
        
        self.logger.info(f"Content Filter initialized. Active categories: {self.active_categories}")

    def should_block_url(self, url, host):
        """Check if URL should be blocked based on patterns and categories"""
        if not self.enabled:
            return False
        
        # Check whitelist first
        if self._is_whitelisted(host):
            return False
        
        # Check blacklist
        if self._is_blacklisted(host):
            self.logger.info(f"Blocked by blacklist: {host}")
            return True
        
        # Check URL against active categories
        url_lower = url.lower()
        host_lower = host.lower()
        
        for category in self.active_categories:
            if category in self.blocked_categories:
                keywords = self.blocked_categories[category]
                for keyword in keywords:
                    if keyword in url_lower or keyword in host_lower:
                        self.logger.info(f"Blocked by category '{category}': {url}")
                        return True
        
        return False

    def should_block_content(self, response_str):
        """Analyze response content for blocked keywords"""
        if not self.enabled:
            return False
        
        # Extract body from response
        body_start = response_str.find('\r\n\r\n')
        if body_start == -1:
            return False
        
        body = response_str[body_start:].lower()
        
        # Check content against active categories
        for category in self.active_categories:
            if category in self.blocked_categories:
                keywords = self.blocked_categories[category]
                
                # Count keyword occurrences
                keyword_count = 0
                for keyword in keywords:
                    keyword_count += body.count(keyword)
                
                # Block if multiple keywords found (threshold: 5)
                if keyword_count >= 5:
                    self.logger.info(f"Blocked by content analysis - category: {category}")
                    return True
        
        return False

    def _is_whitelisted(self, host):
        """Check if host is in whitelist"""
        for domain in self.domain_whitelist:
            if domain in host:
                return True
        return False

    def _is_blacklisted(self, host):
        """Check if host is in blacklist"""
        for domain in self.domain_blacklist:
            if domain in host:
                return True
        return False

    def add_to_blacklist(self, domain):
        """Add domain to blacklist"""
        self.domain_blacklist.add(domain)
        self.logger.info(f"Added to blacklist: {domain}")

    def remove_from_blacklist(self, domain):
        """Remove domain from blacklist"""
        if domain in self.domain_blacklist:
            self.domain_blacklist.remove(domain)
            self.logger.info(f"Removed from blacklist: {domain}")

    def add_to_whitelist(self, domain):
        """Add domain to whitelist"""
        self.domain_whitelist.add(domain)
        self.logger.info(f"Added to whitelist: {domain}")

    def remove_from_whitelist(self, domain):
        """Remove domain from whitelist"""
        if domain in self.domain_whitelist:
            self.domain_whitelist.remove(domain)
            self.logger.info(f"Removed from whitelist: {domain}")

    def enable_category(self, category):
        """Enable blocking for a category"""
        if category in self.blocked_categories:
            self.active_categories.add(category)
            self.logger.info(f"Enabled category: {category}")
            return True
        return False

    def disable_category(self, category):
        """Disable blocking for a category"""
        if category in self.active_categories:
            self.active_categories.remove(category)
            self.logger.info(f"Disabled category: {category}")
            return True
        return False

    def add_keyword_to_category(self, category, keyword):
        """Add custom keyword to category"""
        if category in self.blocked_categories:
            self.blocked_categories[category].append(keyword.lower())
            self.logger.info(f"Added keyword '{keyword}' to category '{category}'")
            return True
        return False

    def get_categories(self):
        """Get all available categories"""
        return list(self.blocked_categories.keys())

    def get_active_categories(self):
        """Get currently active categories"""
        return list(self.active_categories)

    def get_blacklist(self):
        """Get current blacklist"""
        return list(self.domain_blacklist)

    def get_whitelist(self):
        """Get current whitelist"""
        return list(self.domain_whitelist)

    def get_category_keywords(self, category):
        """Get keywords for a specific category"""
        return self.blocked_categories.get(category, [])