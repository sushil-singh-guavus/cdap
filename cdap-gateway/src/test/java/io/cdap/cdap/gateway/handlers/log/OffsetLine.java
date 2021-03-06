/*
 * Copyright © 2016 Cask Data, Inc.
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
 */

package io.cdap.cdap.gateway.handlers.log;

import com.google.common.base.Objects;
import io.cdap.cdap.logging.read.LogOffset;

/**
 * Test {@link LogOffset} object.
 */
class OffsetLine {
  private final LogOffset offset;

  OffsetLine(LogOffset offset) {
    this.offset = offset;
  }

  public LogOffset getOffset() {
    return offset;
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
      .add("offset", offset)
      .toString();
  }
}
