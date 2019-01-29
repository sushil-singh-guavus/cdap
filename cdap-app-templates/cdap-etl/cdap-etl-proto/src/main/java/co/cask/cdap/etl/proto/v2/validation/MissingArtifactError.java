/*
 * Copyright © 2019 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package co.cask.cdap.etl.proto.v2.validation;


import co.cask.cdap.etl.proto.ArtifactSelectorConfig;

import java.util.Objects;

/**
 * An error that occurred due to the plugin artifact for a stage not being found.
 */
public class MissingArtifactError extends StageValidationError {
  private final ArtifactSelectorConfig suggestedArtifact;

  public MissingArtifactError(String message, String stage, ArtifactSelectorConfig suggestedArtifact) {
    super(Type.INVALID_FIELD, message, stage);
    this.suggestedArtifact = suggestedArtifact;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    MissingArtifactError that = (MissingArtifactError) o;
    return Objects.equals(suggestedArtifact, that.suggestedArtifact);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), suggestedArtifact);
  }
}