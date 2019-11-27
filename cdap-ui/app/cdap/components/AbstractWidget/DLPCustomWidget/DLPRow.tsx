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
import FormHelperText from '@material-ui/core/FormHelperText';
import InputLabel from '@material-ui/core/InputLabel';
import * as React from 'react';
import withStyles, { StyleRules } from '@material-ui/core/styles/withStyles';
import Select from '@material-ui/core/Select';
import MenuItem from '@material-ui/core/MenuItem';
import AbstractRow, {
  IAbstractRowProps,
  AbstractRowStyles,
} from 'components/AbstractWidget/AbstractMultiRowWidget/AbstractRow';
import MultiSelect, { IOption } from '../FormInputs/MultiSelect';
import {
  IWidgetProperty,
  IPluginProperty,
  IPropertyFilter,
  PluginProperties,
} from 'components/ConfigurationGroup/types';
import InputFieldDropdown from '../InputFieldDropdown';
import { IconButton } from '@material-ui/core';
import If from 'components/If';
import ExpandLessIcon from '@material-ui/icons/ExpandLess';
import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import FormControl from '@material-ui/core/FormControl';
import ConfigurationGroup, { IConfigurationGroupProps } from 'components/ConfigurationGroup';
import { IErrorObj } from 'components/ConfigurationGroup/utilities';

const styles = (theme): StyleRules => {
  return {
    ...AbstractRowStyles(theme),
    root: {
      minHeight: '50px',
      display: 'grid',
      gridTemplateColumns: '1fr auto auto auto',
      alignItems: 'center',
      '& > button': {
        width: '40px',
        height: '40px',
        margin: 'auto',
        marginTop: '5px',
      },
    },
    inputContainer: {
      display: 'grid',
      gridTemplateColumns: '40px 1fr 30px 1fr 50px 1fr',
      gridGap: '10px',
    },
    errorBorder: {
      border: '2px solid',
      borderColor: theme.palette.red[50],
    },
    disabled: {
      color: `${theme.palette.grey['50']}`,
    },
    separator: {
      textAlign: 'center',
    },
    group: {
      marginLeft: '20px',
      marginTop: '15px',
      marginBottom: '15px',
      '& > div > div': {
        padding: '15px 10px 10px',
      },
    },
    groupTitle: {
      marginBottom: '15px',
      '& > h2': {
        fontSize: '1.2rem',
      },
    },
    errorText: {
      color: theme.palette.red[50],
      marginLeft: '15px',
      marginTop: '5px',
    },
  };
};

interface IErrorConfig {
  transform: string;
  fields: string;
  filters: string;
  transformPropertyId: string;
  isNestedError: boolean;
}

export interface ITransformProp {
  label: string;
  name: string;
  options: IWidgetProperty[];
  supportedTypes?: string[];
  filters?: IPropertyFilter[];
}
export type FilterOption = IOption | string;

interface IDLPRowProps extends IAbstractRowProps<typeof styles> {
  transforms: ITransformProp[];
  filters: FilterOption[];
  extraConfig: any;
}

interface IDLPRowState {
  fields: string;
  transform: string;
  filters: string;
  transformProperties: Record<string, string>;
  expanded?: boolean;
}

type StateKeys = keyof IDLPRowState;

class DLPRow extends AbstractRow<IDLPRowProps, IDLPRowState> {
  public static defaultProps = {
    transforms: [],
    filters: [],
    extraConfig: '',
    expanded: false,
  };

  public state = {
    fields: '',
    transform: '',
    filters: '',
    transformProperties: {},
    expanded: false,
  };

  /**
   * Sample input: fieldName:filterScrope(filter)
   */
  public componentDidMount() {
    try {
      const jsonString = this.props.value;
      const jsonObj = JSON.parse(jsonString);
      this.setState({ ...this.state, ...jsonObj });
    } catch (error) {
      console.log(error);
      this.setState({
        fields: '',
        transform: '',
        filters: '',
        transformProperties: {},
      });
    }
  }

  // Handles onChange for MultiSelect components (filters and fields selectors)
  private handleChangeMultiSelect = (type: StateKeys, e: string) => {
    if (type === 'filters') {
      const noneWasSelected: boolean = this.state.filters.includes('NONE');
      const noneIsSelected: boolean = e.includes('NONE');

      // Ensuring user can't select 'NONE' along with other filters
      // TODO: Use another component for the filters selector (https://issues.cask.co/browse/CDAP-16124)
      if (noneWasSelected && noneIsSelected) {
        e = e.replace('NONE,', '');
      } else if (!noneWasSelected && noneIsSelected) {
        e = 'NONE';
      }
    }

    this.handleChange(type, e);
  };

  // Handles onChange for Select components (transform selector)
  private handleChangeSelect = (type: StateKeys, e) => {
    const value = e.target.value;
    if (value == this.state.transform) {
      return;
    }
    this.handleChange(type, value);
    if (type === 'transform') {
      const transformProps = {};
      this.props.transforms
        .filter((transform) => transform.name === value)[0]
        .options.forEach((element) => {
          transformProps[element.name] = element['widget-attributes'].default || '';
        });
      this.handleChange('transformProperties', transformProps);
      this.handleChange('expanded', Object.keys(transformProps).length > 0);
    }
  };

  private handleChangeTransformOptions(values: Record<string, string>) {
    // Comparing new values to current state
    const newValuesKeys = Object.keys(values);
    const oldValuesKeys = Object.keys(this.state.transformProperties);
    const longerKeysList =
      newValuesKeys.length >= oldValuesKeys.length ? newValuesKeys : oldValuesKeys;
    const longerDict =
      newValuesKeys.length >= oldValuesKeys.length ? values : this.state.transformProperties;
    const shorterKeysList =
      newValuesKeys.length < oldValuesKeys.length ? newValuesKeys : oldValuesKeys;
    const diffs = longerKeysList.filter(
      (key) =>
        !(shorterKeysList.includes(key) || longerDict[key] === '') ||
        (values[key] !== undefined && values[key] !== this.state.transformProperties[key])
    );

    // Only update if there are differences
    if (diffs.length > 0) {
      this.handleChange('transformProperties', values);
    }
  }

  private handleChange = (type: StateKeys, value) => {
    this.setState(
      {
        [type]: value,
      } as Pick<IDLPRowState, StateKeys>,
      () => {
        const { transform, filters } = this.state;

        if (transform.length === 0) {
          this.onChange('');
          return;
        }

        const updatedValue = this.state;
        // updatedValue.expanded = false;
        this.onChange(JSON.stringify(updatedValue));
      }
    );
  };

  public renderInput = () => {
    console.log(this.state);
    const filters = this.props.filters.map((option: FilterOption) => {
      if (typeof option === 'object') {
        return option;
      }

      return {
        id: option,
        label: option,
      };
    });

    const errors = this.props.errors
      ? this.props.errors.filter((err) => {
          try {
            const errorConfig: IErrorConfig = JSON.parse(err.element);
            return (
              errorConfig.fields === this.state.fields &&
              errorConfig.transform === this.state.transform &&
              errorConfig.filters === this.state.filters
            );
          } catch (error) {
            return false;
          }
        })
      : [];

    const transforms = this.props.transforms;
    const inputFieldProps = {
      multiselect: true,
      allowedTypes: [],
    };

    const properties: PluginProperties = {};
    const config: IConfigurationGroupProps = {
      classes: {},
      errors: {},
      values: {},
      pluginProperties: properties,
    };

    const localErrors: IErrorObj[] = [];
    const nestedErrors: IErrorObj[] = [];
    const errorDict = {};
    errors.forEach((err) => {
      try {
        const errorConfig: IErrorConfig = JSON.parse(err.element);
        if (errorConfig.isNestedError) {
          nestedErrors.push(err);
        } else {
          localErrors.push(err);
        }
        errorDict[errorConfig.transformPropertyId] = true;
      } catch (error) {}
    });

    if (this.state.transform !== '') {
      inputFieldProps.allowedTypes =
        transforms.filter((transform) => transform.name == this.state.transform)[0]
          .supportedTypes || [];

      const transform: ITransformProp = this.props.transforms.filter(
        (t) => t.name === this.state.transform
      )[0];
      transform.options.forEach((transProp) => {
        const pluginProp: IPluginProperty = {
          name: transProp.name,
        };
        if (transProp['widget-attributes']) {
          if (transProp['widget-attributes'].macro) {
            pluginProp.macroSupported = transProp['widget-attributes'].macro;
          }
          if (transProp['widget-attributes'].description) {
            pluginProp.description = transProp['widget-attributes'].description;
          }
          if (transProp['widget-attributes'].required) {
            pluginProp.required = transProp['widget-attributes'].required;
          }
        }
        properties[transProp.name] = pluginProp;
      });

      config.pluginProperties = properties;
      config.errors = {};
      nestedErrors.forEach((err) => {
        try {
          const errorConfig: IErrorConfig = JSON.parse(err.element);
          const errorObj = { msg: err.msg };
          if (errorConfig.transformPropertyId in config.errors) {
            config.errors[errorConfig.transformPropertyId].push(errorObj);
          } else {
            config.errors[errorConfig.transformPropertyId] = [errorObj];
          }
          errorDict[errorConfig.transformPropertyId] = true;
        } catch (error) {}
      });
      config.widgetJson = {
        'configuration-groups': [
          {
            label: transform.label + ' properties',
            properties: transform.options,
          },
        ],
        filters: transform.filters,
      };
      config.values = this.state.transformProperties;
      config.classes = this.props.classes;
      config.onChange = this.handleChangeTransformOptions.bind(this);

      if (nestedErrors.length > 0) {
        this.handleChange('expanded', true);
      }
    }

    return (
      <React.Fragment>
        <div>
          <div className={this.props.classes.inputContainer}>
            <span className={this.props.classes.separator}>Apply</span>
            <FormControl>
              <Select
                classes={{ disabled: this.props.classes.disabled }}
                value={this.state.transform}
                onChange={this.handleChangeSelect.bind(this, 'transform')}
                displayEmpty={true}
                disabled={false}
              >
                {transforms.map((option) => {
                  return (
                    <MenuItem value={option.name} key={option.name}>
                      {option.label}
                    </MenuItem>
                  );
                })}
              </Select>
            </FormControl>
            <span className={this.props.classes.separator}>on</span>
            <MultiSelect
              disabled={false}
              value={this.state.filters}
              widgetProps={{ options: filters }}
              onChange={this.handleChangeMultiSelect.bind(this, 'filters')}
            />
            <span className={this.props.classes.separator}>within</span>
            <InputFieldDropdown
              widgetProps={inputFieldProps}
              value={this.state.fields}
              onChange={this.handleChangeMultiSelect.bind(this, 'fields')}
              disabled={false}
              extraConfig={this.props.extraConfig}
            />
          </div>

          {localErrors.map((err) => {
            try {
              const errorConfig: IErrorConfig = JSON.parse(err.element);
              if (!errorConfig.isNestedError) {
                return <div className={this.props.classes.errorText}>{err.msg}</div>;
              }
            } catch (error) {}
          })}
          <div className={this.props.classes.transformContainer}>
            <If
              condition={
                this.state.transform !== '' &&
                Object.keys(this.state.transformProperties).length > 0 &&
                this.state.expanded
              }
            >
              <ConfigurationGroup {...config} />
            </If>
          </div>
        </div>

        <If condition={this.state.expanded}>
          <IconButton
            color="primary"
            onClick={() => {
              this.handleChange('expanded', !this.state.expanded);
            }}
          >
            <ExpandLessIcon />
          </IconButton>
        </If>

        <If condition={!this.state.expanded}>
          <IconButton
            color="primary"
            onClick={() => {
              this.handleChange('expanded', !this.state.expanded);
            }}
            disabled={Object.keys(this.state.transformProperties).length == 0}
          >
            <ExpandMoreIcon />
          </IconButton>
        </If>
      </React.Fragment>
    );
  };
}

const StyledDLPRow = withStyles(styles)(DLPRow);
export default StyledDLPRow;
