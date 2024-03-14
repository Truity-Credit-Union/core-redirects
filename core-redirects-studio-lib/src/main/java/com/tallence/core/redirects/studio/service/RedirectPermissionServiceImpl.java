/*
 * Copyright 2019 Tallence AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.tallence.core.redirects.studio.service;

import com.coremedia.cap.content.Content;
import com.coremedia.cap.content.ContentRepository;
import com.coremedia.cap.content.ContentType;
import com.coremedia.cap.content.authorization.AccessControl;
import com.coremedia.cap.content.authorization.Right;
import com.coremedia.cap.springframework.security.impl.CapUserDetails;
import com.coremedia.cap.user.Group;
import com.coremedia.cap.user.User;
import com.coremedia.cap.user.UserRepository;
import com.tallence.core.redirects.model.SourceUrlType;
import com.tallence.core.redirects.studio.model.RedirectUpdateProperties;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import com.coremedia.cap.springframework.security.SpringSecurityCapUserFinder;
import com.coremedia.cap.springframework.security.impl.CapSpringSecurityCapUserFinder;

import javax.annotation.PostConstruct;

import com.coremedia.cap.common.CapConnection;


import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import static com.tallence.core.redirects.studio.model.RedirectUpdateProperties.SOURCE_URL_TYPE;

/**
 * Default implementation of a {@link RedirectPermissionService}.
 * With this implementation, the system checks whether the read and write authorizations are present on the folder when
 * creating, editing, deleting, and reading forwards. Redirects with a regex can only be edited, deleted or created by
 * administrators.
 */
public class RedirectPermissionServiceImpl implements RedirectPermissionService {

  /**
   * Creates the {@link SpringSecurityCapUserFinder} bean that is used
   * to find a {@link User} for a given {@link org.springframework.security.core.Authentication} object.
   * <p>
   * It can be replaced with a custom {@link SpringSecurityCapUserFinder} bean, see {@link ConditionalOnMissingBean}.
   *
   * @param capConnection the {@link CapConnection} (bean)
   * @return the {@link SpringSecurityCapUserFinder} (bean)
   */
  @Bean
  @ConditionalOnMissingBean
  public SpringSecurityCapUserFinder redirectSpringSecurityCapUserFinder(CapConnection capConnection) {
    CapSpringSecurityCapUserFinder capSpringSecurityCapUserFinder = new CapSpringSecurityCapUserFinder();
    capSpringSecurityCapUserFinder.setCapConnection(capConnection);
    capSpringSecurityCapUserFinder.setIdentifyByName(true);
    return capSpringSecurityCapUserFinder;
  }

  /**
   * Creates the {@link AuthenticationManager} bean, using the default bean name is that is defined
   * by {@link BeanIds#AUTHENTICATION_MANAGER}.
   * <p>
   * It can be replaced with a custom {@link AuthenticationManager} bean, see {@link ConditionalOnMissingBean}.
   *
   * @param capAuthenticationProvider the {@link #capAuthenticationProvider} (bean)
   * @return the {@link AuthenticationManager} (bean)
   */
  @Bean
  @ConditionalOnMissingBean
  public AuthenticationManager redirectAuthenticationManager(AuthenticationProvider capAuthenticationProvider) {
    return new ProviderManager(capAuthenticationProvider);
  }

  private static final Logger LOG = LoggerFactory.getLogger(RedirectPermissionServiceImpl.class);


  private final ContentRepository contentRepository;
  private final UserRepository userRepository;
  private final CapConnection capConnection;
  private final String regexGroupName;
  private final String targetUrlGroupName;
  private Group regexGroup;
  private Group targetUrlGroup;
  private ContentType redirectContentType;

 /** public SpringSecurityCapUserFinder getSpringSecurityCapUserFinder() {
    return springSecurityCapUserFinder;
  }

  public void setSpringSecurityCapUserFinder(SpringSecurityCapUserFinder springSecurityCapUserFinder) {
    this.springSecurityCapUserFinder = springSecurityCapUserFinder;
  }**/

  @Autowired
  public RedirectPermissionServiceImpl(ContentRepository contentRepository, UserRepository userRepository,
                                       CapConnection capConnection,
                                       @Value("${core.redirects.permissions.targetUrlGroup:}") String targetUrlGroupName,
                                       @Value("${core.redirects.permissions.regexGroup:}") String regexGroupName) {
    LOG.debug("######### RedirectPermissionServiceImpl contructor DEBUG #########");
    LOG.info("######### RedirectPermissionServiceImpl contructor INFO #########");
    LOG.warn("######### RedirectPermissionServiceImpl contructor WARN #########");
    LOG.error("######### RedirectPermissionServiceImpl contructor ERROR #########");
    this.contentRepository = contentRepository;
    this.userRepository = userRepository;
    this.capConnection = capConnection;
    this.redirectContentType = contentRepository.getContentType("Redirect");
    this.regexGroupName = regexGroupName;
    this.targetUrlGroupName = targetUrlGroupName;
  }

  @Override
  public boolean mayRead(Content rootFolder) {
    return contentRepository.getAccessControl().mayPerform(rootFolder, this.redirectContentType, Right.READ);
  }

  @Override
  public boolean mayCreate(Content rootFolder, RedirectUpdateProperties updateProperties) {
    LOG.warn("######### RedirectPermissionServiceImpl mayCreate #########");
    Boolean toBePublished = updateProperties.getActive();
    LOG.warn("######### RedirectPermissionServiceImpl toBePublished #########" + toBePublished);

    if (toBePublished == null) {
      //It should not be null
      LOG.warn("The active flag should not be null!");
      return false;
    }

    return mayPerformWrite(rootFolder) &&
            (!toBePublished || mayPerformPublish(rootFolder)) &&
            isAllowedForTargetUrl(updateProperties.getTargetUrl()) &&
            isAllowedForRegex(isUserAllowedForRegex(), updateProperties.getSourceUrlType());
  }

  @Override
  public boolean mayDelete(Content redirect) {
    //Only admins may delete regex redirects
    boolean administrator = isUserAllowedForRegex();

    boolean published = contentRepository.getPublicationService().isPublished(redirect);
    return mayPerformDelete(redirect) &&
            (!published || mayPerformPublish(redirect)) &&
            isAllowedForRegex(administrator, SourceUrlType.asSourceUrlType(redirect.getString(SOURCE_URL_TYPE)));
  }

  @Override
  public boolean mayWrite(Content redirect, RedirectUpdateProperties updateProperties) {
    LOG.warn("######### RedirectPermissionServiceImpl mayCreate #########");
    //Only admins may edit regex redirects
    boolean administrator = isUserAllowedForRegex();
    LOG.warn("######### RedirectPermissionServiceImpl mayWrite administrator #########" + administrator);

    //publication rights are required if the document is already published or if it is meant to be,
    // according to the given properties.
    boolean alreadyPublished = contentRepository.getPublicationService().isPublished(redirect);
    LOG.warn("######### RedirectPermissionServiceImpl mayWrite alreadyPublished #########" + alreadyPublished);
    Boolean publishDocument = updateProperties.getActive();
    LOG.warn("######### RedirectPermissionServiceImpl mayWrite publishDocument #########" + publishDocument);
    boolean requirePublicationRights = Boolean.TRUE.equals(publishDocument) || alreadyPublished;
    LOG.warn("######### RedirectPermissionServiceImpl mayWrite requirePublicationRights #########" + requirePublicationRights);

    return mayPerformWrite(redirect) &&
            (!requirePublicationRights || mayPerformPublish(redirect)) &&
            isAllowedForTargetUrl(updateProperties.getTargetUrl()) &&
            isAllowedForRegex(administrator, updateProperties.getSourceUrlType()) &&
            isAllowedForRegex(administrator, SourceUrlType.asSourceUrlType(redirect.getString(SOURCE_URL_TYPE)));
  }

  @Override
  public RedirectRights resolveRights(Content rootFolder) {
    LOG.warn("######### RedirectPermissionServiceImpl resolveRights rootFolder #########" + rootFolder.getId());
    return new RedirectRights(mayPerformWrite(rootFolder), mayPerformPublish(rootFolder), isUserAllowedForRegex(), isUserAllowedForTargetUrlUsage());
  }

  private boolean isAllowedForRegex(boolean mayUseRegex, SourceUrlType sourceType) {
    return mayUseRegex || !SourceUrlType.REGEX.equals(sourceType);
  }

  private boolean isAllowedForTargetUrl(String targetUrl) {
    return isUserAllowedForTargetUrlUsage() || StringUtils.isEmpty(targetUrl);
  }

  private boolean mayPerformWrite(Content content) {
    AccessControl accessControl = contentRepository.getAccessControl();
    LOG.warn("######### RedirectPermissionServiceImpl mayPerformWrite accessControl #########" + accessControl);

    return accessControl.mayPerform(content, redirectContentType, Right.WRITE);
  }

  private boolean mayPerformPublish(Content content) {
    AccessControl accessControl = contentRepository.getAccessControl();
    LOG.warn("######### RedirectPermissionServiceImpl mayPerformPublish accessControl #########" + accessControl);
    return accessControl.mayPerform(content, redirectContentType, Right.PUBLISH);
  }

  private boolean mayPerformDelete(Content content) {
    AccessControl accessControl = contentRepository.getAccessControl();
    LOG.warn("######### RedirectPermissionServiceImpl mayPerformDelete accessControl #########" + accessControl);
    return accessControl.mayPerform(content, redirectContentType, Right.DELETE);
  }

  private boolean isUserAllowedForRegex() {
    LOG.warn("######### RedirectPermissionServiceImpl isUserAllowedForRegex #########");
    User user = getUser();
    LOG.warn("######### RedirectPermissionServiceImpl isUserAllowedForRegex user #########"+ user);
    if (user == null) {
      throw new IllegalStateException("No user could be found");
    }

    if (regexGroup != null) {
      return user.isMemberOf(regexGroup);
    } else {
      return user.isAdministrative();
    }
  }

  private boolean isUserAllowedForTargetUrlUsage() {
    LOG.warn("######### RedirectPermissionServiceImpl isUserAllowedForTargetUrlUsage #########");
    User user = getUser();
    LOG.warn("######### RedirectPermissionServiceImpl isUserAllowedForTargetUrlUsage user #########"+ user);
    if (user == null) {
      throw new IllegalStateException("No user could be found");
    }

    if (targetUrlGroup != null) {
      return user.isMemberOf(targetUrlGroup) || user.isAdministrative();
    } else {
      return "*".equalsIgnoreCase(targetUrlGroupName);
    }
  }

  private User getUser() {
    LOG.warn("######### RedirectPermissionServiceImpl getUser ########");

    try {
      LOG.warn("######### RedirectPermissionServiceImpl alternative strategy ########");
      SpringSecurityCapUserFinder finder = redirectSpringSecurityCapUserFinder(contentRepository.getConnection());
      LOG.warn("######### RedirectPermissionServiceImpl finder #########" + finder);
      User temp = finder.findCapUser(SecurityContextHolder.getContext().getAuthentication());
      LOG.warn("######### RedirectPermissionServiceImpl finder user #########"+ temp);
      LOG.warn("######### RedirectPermissionServiceImpl finder tempId #########"+ temp.getId());
      Content home = temp.getHomeFolder();
      LOG.warn("######### RedirectPermissionServiceImpl finder home #########"+ home.getId());
    } catch (Exception e) {
      LOG.error("######### RedirectPermissionServiceImpl exception #########"+ e.getMessage());
    }
    LOG.warn("######### RedirectPermissionServiceImpl getUser user ########"+ capConnection.getSession().getUser());
    return capConnection.getSession().getUser();
  }

  private String getUserId() {
    try {
      LOG.warn("######### RedirectPermissionServiceImpl alternative strategy ########");
      SpringSecurityCapUserFinder finder = redirectSpringSecurityCapUserFinder(contentRepository.getConnection());
      LOG.warn("######### RedirectPermissionServiceImpl finder #########" + finder);
      User temp = finder.findCapUser(SecurityContextHolder.getContext().getAuthentication());
      LOG.warn("######### RedirectPermissionServiceImpl finder user #########"+ temp);
      LOG.warn("######### RedirectPermissionServiceImpl finder tempId #########"+ temp.getId());
      Content home = temp.getHomeFolder();
      LOG.warn("######### RedirectPermissionServiceImpl finder home #########"+ home.getId());
    } catch (Exception e) {
      LOG.error("######### RedirectPermissionServiceImpl exception #########"+ e.getMessage());
    }


    LOG.warn("######### RedirectPermissionServiceImpl getUserId #########");
    LOG.warn("######### RedirectPermissionServiceImpl getUserId SecurityContextHolder.getContext().getAuthentication() #########"+ SecurityContextHolder.getContext().getAuthentication());
    Object user = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    LOG.warn("######### RedirectPermissionServiceImpl getUserId user #########"+ user);
    if (user instanceof CapUserDetails) {
      LOG.warn("######### RedirectPermissionServiceImpl getUserId userId #########"+ ((CapUserDetails) user).getUserId());
      return ((CapUserDetails) user).getUserId();
    } else {
      throw new IllegalStateException("Could not get userId from authenticated user.");
    }
  }

  @PostConstruct
  public void postConstruct() {
    if (StringUtils.isNotBlank(regexGroupName)) {
      regexGroup = userRepository.getGroupByName(regexGroupName);
      if (regexGroup == null) {
        LOG.error("Configured regexGroup [{}] not found in CMS!", regexGroupName);
      }
    }

    if (StringUtils.isNotBlank(targetUrlGroupName)) {
      targetUrlGroup = userRepository.getGroupByName(targetUrlGroupName);
      if (targetUrlGroup == null) {
        LOG.error("Configured targetUrlGroup [{}] not found in CMS!", targetUrlGroupName);
      }
    }
  }
}
