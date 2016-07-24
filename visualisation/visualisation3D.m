function [] = visualisation3D(filename)
    log = fopen(filename, 'r');

    surface_plot(log, 16)
    fclose(log);
end

function [] = surface_plot(log, entries)
    % parse number of testcases from first line
    input = textscan(log,'%s',2,'delimiter','=');
    nroftestcases = str2num(input{1}{2});

    data = {};
    for i=1:nroftestcases
        % for each testcase parse testcase id, number of associated data 
        % entries, number of message entries
        trash = textscan(log,'%s',3,'delimiter',';');

        testcaseid = textscan(trash{1}{1},'%s %d','delimiter','=');
        testcaseid = testcaseid{2};

        numberofadentries = textscan(trash{1}{2}, '%s %d','delimiter','=');
        numberofadentries = numberofadentries{2};

        numberofmsgentries = textscan(trash{1}{3}, '%s %d','delimiter','=');
        numberofmsgentries = numberofmsgentries{2};
        
        % for each testcase trash second line with metadata
        % extract lines into data cellarray
        trash = textscan(log,'%s',4,'delimiter',';');
        data{i} = textscan(log,'%s %f %f %f',numberofadentries*numberofmsgentries,'delimiter',';');
        
        if numberofadentries < 2
            continue
        end

        X = data{i}{3};   %mlen
        Y = data{i}{4};   %adlen
        Z = data{i}{2};   %time
        
        highestvalue = max(Z);
        smallestvalue = min(Z);
        
        x = zeros(numberofmsgentries, numberofadentries);
        y = zeros(numberofmsgentries, numberofadentries);
        z = zeros(numberofmsgentries, numberofadentries);
        for j=1:numberofadentries
            x(:,j) = X(((j-1)*(numberofmsgentries))+1:(j*(numberofmsgentries)));
            y(:,j) = Y(((j-1)*(numberofmsgentries))+1:(j*(numberofmsgentries)));
            z(:,j) = Z(((j-1)*(numberofmsgentries))+1:(j*(numberofmsgentries)));
        end
         
        figure; 
        surf(x, y, z);
        hold on;

        k = 128;
        while k <= 2048
            h = 128;
            while h <= 2048 
                f = plot3(h,k,z(h/128,k/128),'k.');
                setDataTip(f);
                h = h * 2;
            end
            k = k * 2;
        end 

        hold off;

        title(data{i}{1}{1})
        xlabel('Message (bytes)')
        ylabel('Associated Data (bytes)')
        zlabel('Performance (cycles/byte)')
        
        %     XMIN XMAX YMIN YMAX ZMIN ZMAX
        axis([0, 2048, 0, 2048, smallestvalue, highestvalue]);
        set(gca,'XTick',[0:128:2048]);
        set(gca,'YTick',[0:128:2048]);
        set(gca,'fontsize',22);
        set(gca,'XTickLabelRotation',330);
        set(gca,'YTickLabelRotation',30);
        
        alldatacursors = findall(gcf,'type','hggroup');
        set(alldatacursors,'FontSize',18);
        
        view(135, 20);
    end
end


function [] = setDataTip(fighandle)
% First get the figure's data-cursor mode, activate it, and set some of its properties
cursorMode = datacursormode(gcf);
%set(cursorMode, 'enable','on', 'UpdateFcn',@setDataTipTxt, 'NewDataCursorOnClick',false);)
set(cursorMode, 'UpdateFcn',@setDataTipTxt);
set(cursorMode,'DisplayStyle','datatip','SnapToDataVertex','off','Enable','on')
% Note: the optional @setDataTipTxt is used to customize the data-tip's appearance
 
% Note: the following code was adapted from %matlabroot%\toolbox\matlab\graphics\datacursormode.m
% Create a new data tip
hTarget = handle(fighandle);
hDatatip = cursorMode.createDatatip(hTarget);
 
% Create a copy of the context menu for the datatip:
set(hDatatip,'UIContextMenu', get(cursorMode,'UIContextMenu'));
set(hDatatip,'HandleVisibility','off');
set(hDatatip,'Host',hTarget);
%set(hDatatip,'ViewStyle','datatip');
set(hDatatip,'BackgroundColor', [1, 1, 1]);
 
% Set the data-tip orientation to top-right rather than auto
set(hDatatip,'OrientationMode','manual');
set(hDatatip,'Orientation','topright');
 
% Update the datatip marker appearance
set(hDatatip, 'MarkerSize',5, 'MarkerFaceColor','none', ...
              'MarkerEdgeColor','k', 'Marker','o', 'HitTest','off');
end


function txt = setDataTipTxt(~,event_obj)
% Customizes text of data tips
pos = get(event_obj,'Position');
txt = {['cpb: ',num2str(pos(3),4)]};
end

