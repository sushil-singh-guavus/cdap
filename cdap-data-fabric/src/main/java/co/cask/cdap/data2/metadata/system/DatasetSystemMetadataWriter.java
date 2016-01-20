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

package co.cask.cdap.data2.metadata.system;

import co.cask.cdap.api.data.batch.BatchReadable;
import co.cask.cdap.api.data.batch.BatchWritable;
import co.cask.cdap.api.data.batch.RecordScannable;
import co.cask.cdap.api.dataset.Dataset;
import co.cask.cdap.api.dataset.DatasetProperties;
import co.cask.cdap.api.dataset.lib.ObjectMappedTableProperties;
import co.cask.cdap.api.dataset.table.Table;
import co.cask.cdap.data.dataset.SystemDatasetInstantiator;
import co.cask.cdap.data.dataset.SystemDatasetInstantiatorFactory;
import co.cask.cdap.data2.metadata.store.MetadataStore;
import co.cask.cdap.proto.Id;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * A {@link AbstractSystemMetadataWriter} for a {@link Id.DatasetInstance dataset}.
 */
public class DatasetSystemMetadataWriter extends AbstractSystemMetadataWriter {
  public static final String EXPLORE_TAG = "explore";
  public static final String BATCH_TAG = "batch";

  private final Id.DatasetInstance dsInstance;
  private final String dsType;
  private final DatasetProperties dsProperties;
  private final SystemDatasetInstantiatorFactory dsInstantiatorFactory;

  public DatasetSystemMetadataWriter(MetadataStore metadataStore,
                                     SystemDatasetInstantiatorFactory dsInstantiatorFactory,
                                     Id.DatasetInstance dsInstance, DatasetProperties dsProperties,
                                     @Nullable String dsType) {
    super(metadataStore, dsInstance);
    this.dsInstance = dsInstance;
    this.dsType = dsType;
    this.dsProperties = dsProperties;
    this.dsInstantiatorFactory = dsInstantiatorFactory;
  }

  @Override
  Map<String, String> getSystemPropertiesToAdd() {
    ImmutableMap.Builder<String, String> properties = ImmutableMap.builder();
    Map<String, String> datasetProperties = dsProperties.getProperties();
    if (dsType != null) {
      properties.put("type", dsType);
    }
    if (datasetProperties.containsKey(Table.PROPERTY_TTL)) {
      properties.put(TTL_KEY, datasetProperties.get(Table.PROPERTY_TTL));
    }
    return properties.build();
  }

  @Override
  String[] getSystemTagsToAdd() {
    List<String> tags = new ArrayList<>();
    tags.add(dsInstance.getId());
    try (SystemDatasetInstantiator dsInstantiator = dsInstantiatorFactory.create();
         Dataset dataset = dsInstantiator.getDataset(dsInstance)) {
      if (dataset instanceof RecordScannable) {
        tags.add(EXPLORE_TAG);
      }
      if (dataset instanceof BatchReadable || dataset instanceof BatchWritable) {
        tags.add(BATCH_TAG);
      }
    } catch (IOException e) {
      throw Throwables.propagate(e);
    }
    return tags.toArray(new String[tags.size()]);
  }

  @Nullable
  @Override
  String getSchemaToAdd() {
    Map<String, String> datasetProperties = dsProperties.getProperties();
    String schemaStr = null;
    if (datasetProperties.containsKey(DatasetProperties.SCHEMA)) {
      schemaStr = datasetProperties.get(DatasetProperties.SCHEMA);
    } else if (datasetProperties.containsKey(ObjectMappedTableProperties.OBJECT_SCHEMA)) {
      // If it is an ObjectMappedTable, the schema is in a property called 'object.schema'
      schemaStr = datasetProperties.get(ObjectMappedTableProperties.OBJECT_SCHEMA);
    }
    return schemaStr;
  }
}
