package com.tallence.core.redirects.cae;

import com.coremedia.blueprint.base.links.ContentLinkBuilder;
import com.coremedia.blueprint.common.contentbeans.CMLinkable;
import com.coremedia.blueprint.common.contentbeans.CMNavigation;
import com.coremedia.blueprint.common.navigation.Navigation;
import com.coremedia.blueprint.common.services.context.ContextHelper;
import com.coremedia.cap.content.Content;
import com.coremedia.objectserver.web.links.Link;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;
import java.util.Optional;

import static com.coremedia.blueprint.base.links.UriConstants.RequestParameters.VIEW_PARAMETER;

@Link
public class CMLinkableLinkHandler{




  @Autowired
  private ContextHelper contextHelper;
  @Autowired
  private ContentLinkBuilder contentLinkBuilder;

  @Link(type = CMLinkable.class)
  @Nullable
  public UriComponents buildLinkableLink(CMLinkable linkable, String viewName, Map<String, Object> linkParameters) {
    UriComponentsBuilder ucb = buildLinkForLinkableInternal(linkable, viewName, linkParameters).orElse(null);
    return ucb==null ? null : ucb.build();
  }

  @NonNull
  protected Optional<UriComponentsBuilder> buildLinkForLinkableInternal(@NonNull CMLinkable linkable,
                                                                        @Nullable String viewName,
                                                                        @NonNull Map<String, Object> linkParameters) {
    Navigation context = getNavigation(linkable);

    if (context == null) {
      return Optional.empty();
    }

    return buildLink(linkable, context, viewName, linkParameters);
  }

  protected Navigation getNavigation(CMLinkable target) {
    return contextHelper.contextFor(target);
  }

  @NonNull
  private Optional<UriComponentsBuilder> buildLink(@NonNull CMLinkable linkable,
                                                   @NonNull Navigation navigationContext,
                                                   @Nullable String viewName,
                                                   @NonNull Map<String, Object> linkParameters) {
    Content targetContent = linkable.getContent();
    Content navigationContent = ((CMNavigation) navigationContext).getContent();

    UriComponentsBuilder uriComponentsBuilder = contentLinkBuilder
            .buildLinkForPage(targetContent, navigationContent);
    if (uriComponentsBuilder == null) {
      return Optional.empty();
    }

    // add optional view query parameter
    if (viewName != null) {
      uriComponentsBuilder.queryParam(VIEW_PARAMETER, viewName);
    }

    return Optional.of(uriComponentsBuilder);
  }
}
