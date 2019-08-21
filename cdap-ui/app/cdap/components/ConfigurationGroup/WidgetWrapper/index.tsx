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
 */

import * as React from 'react';
import PropTypes from 'prop-types';
import withStyles, { WithStyles, StyleRules } from '@material-ui/core/styles/withStyles';
import { IWidgetProperty, IPluginProperty } from 'components/ConfigurationGroup/types';
import DescriptionTooltip from 'components/ConfigurationGroup/PropertyRow/DescriptionTooltip';
import AbstractWidget from 'components/AbstractWidget';
import classnames from 'classnames';
import { objectQuery } from 'services/helpers';
import If from 'components/If';
import ThemeWrapper from 'components/ThemeWrapper';

const styles = (theme): StyleRules => {
  return {
    widgetWrapper: {
      border: `1px solid`,
      borderColor: theme.palette.grey[300],
      borderRadius: 6,
      position: 'relative',
      padding: '7px 10px 5px',
    },
    label: {
      fontSize: 12,
      position: 'absolute',
      top: -10,
      left: 15,
      padding: '0 5px',
      backgroundColor: theme.palette.white[50],
    },
    required: {
      fontSize: 14,
      marginLeft: 5,
      lineHeight: '12px',
      verticalAlign: 'middle',
    },
    widgetContainer: {
      width: 'calc(100% - 30px)',
    },
    tooltipContainer: {
      position: 'absolute',
      right: 5,
      top: 10,
    },
    focus: {
      borderColor: theme.palette.blue[200],
      '& $label': {
        color: theme.palette.blue[100],
      },
    },
  };
};

interface IWidgetWrapperProps extends WithStyles<typeof styles> {
  widgetProperty: IWidgetProperty;
  pluginProperty: IPluginProperty;
  value: string;
  onChange: (value: string) => void;
  updateAllProperties: (values) => void;
  extraConfig: any;
  disabled: boolean;
  hideDescription?: boolean;
}

const WidgetWrapperView: React.FC<IWidgetWrapperProps> = ({
  widgetProperty,
  pluginProperty,
  value,
  onChange,
  updateAllProperties,
  extraConfig,
  disabled,
  hideDescription,
  classes,
}) => {
  const widgetType = objectQuery(widgetProperty, 'widget-type');
  const [isFocused, setIsFocused] = React.useState<boolean>(false);

  function onFocus() {
    setIsFocused(true);
  }

  function onBlur() {
    setIsFocused(false);
  }

  return (
    <div
      className={classnames(classes.widgetWrapper, { [classes.focus]: isFocused && !disabled })}
      onFocus={onFocus}
      onBlur={onBlur}
    >
      <div className={classes.label}>
        {widgetProperty.label}
        <If condition={pluginProperty.required}>
          <span className={classes.required}>*</span>
        </If>
      </div>
      <div className={classes.widgetContainer}>
        <AbstractWidget
          type={widgetType}
          value={value}
          onChange={onChange}
          updateAllProperties={updateAllProperties}
          widgetProps={widgetProperty['widget-attributes']}
          extraConfig={extraConfig}
          disabled={disabled}
        />
      </div>
      <If condition={!hideDescription}>
        <div className={classes.tooltipContainer}>
          <DescriptionTooltip description={pluginProperty.description} />
        </div>
      </If>
    </div>
  );
};

const WidgetWrapper = withStyles(styles)(WidgetWrapperView);
export default WidgetWrapper;

export function WrappedWidgetWrapper(props) {
  return (
    <ThemeWrapper>
      <WidgetWrapper {...props} />
    </ThemeWrapper>
  );
}

(WrappedWidgetWrapper as any).propTypes = {
  widgetProperty: PropTypes.object,
  pluginProperty: PropTypes.object,
  value: PropTypes.string,
  onChange: PropTypes.func,
  extraConfig: PropTypes.object,
  disabled: PropTypes.bool,
  hideDescription: PropTypes.bool,
};
